//! WASMI host-call interface implementation.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use std::{boxed::Box, convert::TryFrom, string::ToString, vec::Vec};

use platform_services::{getrandom, result};

use wasmi::{
    Error, ExternVal, Externals, FuncInstance, FuncRef, GlobalDescriptor, GlobalRef, HostError,
    MemoryDescriptor, MemoryRef, Module, ModuleImportResolver, ModuleInstance, ModuleRef,
    RuntimeArgs, RuntimeValue, Signature, TableDescriptor, TableRef, Trap, TrapKind, ValueType,
};

use crate::hcall::buffer::VFS;
use crate::hcall::common::{
    EngineReturnCode, EntrySignature, ExecutionEngine, FatalEngineError, HostProvisioningError,
    HCALL_GETRANDOM_NAME, HCALL_HAS_PREVIOUS_RESULT_NAME, HCALL_INPUT_COUNT_NAME,
    HCALL_INPUT_SIZE_NAME, HCALL_PREVIOUS_RESULT_SIZE_NAME, HCALL_READ_INPUT_NAME,
    HCALL_READ_PREVIOUS_RESULT_NAME, HCALL_READ_STREAM_NAME, HCALL_STREAM_COUNT_NAME,
    HCALL_STREAM_SIZE_NAME, HCALL_WRITE_OUTPUT_NAME,
};
#[cfg(any(feature = "std", feature = "tz", feature = "nitro"))]
use std::sync::{Arc, Mutex};
#[cfg(feature = "sgx")]
use std::sync::{Arc, SgxMutex as Mutex};
use veracruz_utils::policy::principal::Principal;

////////////////////////////////////////////////////////////////////////////////
// The WASMI host provisioning state.
////////////////////////////////////////////////////////////////////////////////

#[typetag::serde]
impl HostError for FatalEngineError {}

/// The return type for H-Call implementations.
///
/// From *the viewpoint of the host* a H-call can either fail spectacularly
/// with a runtime trap, in which case `Err(err)` is returned, with `err`
/// detailing what went wrong, and the Veracruz host thereafter terminating
/// or otherwise entering an error state, or succeeds with `Ok(())`.
///
/// From *the viewpoint of the WASM program* a H-call can either fail
/// spectacularly, as above, in which case WASM program execution is aborted
/// with the WASM program itself not being able to do anything about this,
/// succeeds with the desired effect and a success error code returned, or
/// fails with a recoverable error in which case the error code details what
/// went wrong and what can be done to fix it.
pub(crate) type HCallError = Result<EngineReturnCode, FatalEngineError>;

/// The WASMI host provisioning state: the `HostProvisioningState` with the
/// Module and Memory type-variables specialised to WASMI's `ModuleRef` and
/// `MemoryRef` type.
pub(crate) struct WasmiHostProvisioningState {
    /// The VFS installed to this execution
    vfs: Arc<Mutex<VFS>>,
    /// A reference to the WASM program module that will actually execute on
    /// the input data sources.
    program_module: Option<ModuleRef>,
    /// A reference to the WASM program's linear memory (or "heap").
    memory: Option<MemoryRef>,
    /// Ref to the program that is executed
    program: Principal,
}

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// The name of the WASM program's entry point.
const ENTRY_POINT_NAME: &'static str = "main";
/// The name of the WASM program's linear memory.
const LINEAR_MEMORY_NAME: &'static str = "memory";

/// H-call code for the `__veracruz_hcall_input_count` H-call.
const HCALL_INPUT_COUNT_CODE: usize = 0;
/// H-call code for the `__veracruz_hcall_input_size` H-call.
const HCALL_INPUT_SIZE_CODE: usize = 1;
/// H-call code for the `__veracruz_hcall_read_input` H-call.
const HCALL_READ_INPUT_CODE: usize = 2;
/// H-call code for the `__veracruz_hcall_write_output` H-call.
const HCALL_WRITE_OUTPUT_CODE: usize = 3;
/// H-call code for the `__veracruz_hcall_getrandom` H-call.
const HCALL_GETRANDOM_CODE: usize = 4;
/// H-call code for the `__veracruz_hcall_read_previous_result` H-call.
const HCALL_READ_PREVIOUS_RESULT_CODE: usize = 5;
/// H-call code for the `__veracruz_hcall_previous_result_size` H-call.
const HCALL_PREVIOUS_RESULT_SIZE_CODE: usize = 6;
/// H-call code for the `__veracruz_hcall_has_previous_result` H-call.
const HCALL_HAS_PREVIOUS_RESULT_CODE: usize = 10;
/// H-call code for the `__veracruz_hcall_stream_count` H-call.
const HCALL_STREAM_COUNT_CODE: usize = 7;
/// H-call code for the `__veracruz_hcall_stream_size` H-call.
const HCALL_STREAM_SIZE_CODE: usize = 8;
/// H-call code for the `__veracruz_hcall_read_stream` H-call.
const HCALL_READ_STREAM_CODE: usize = 9;

////////////////////////////////////////////////////////////////////////////////
// Function well-formedness checks.
////////////////////////////////////////////////////////////////////////////////

/// Checks the function signature, `signature`, has the correct type for the
/// `__veracruz_hcall_input_count()` function.  This is:
///
/// ```C
/// uint32_t __veracruz_hcall_input_count(void);
/// ```
///
#[inline]
fn check_input_count_signature(signature: &Signature) -> bool {
    signature.params() == [ValueType::I32] && signature.return_type() == Some(ValueType::I32)
}

/// Checks the function signature, `signature`, has the correct type for the
/// `__veracruz_hcall_input_size()` function.  This is:
///
/// ```C
/// enum veracruz_status_t __veracruz_hcall_input_size(uint32_t ix, uint32_t *sz);
/// ```
#[inline]
fn check_input_size_signature(signature: &Signature) -> bool {
    signature.params() == [ValueType::I32, ValueType::I32]
        && signature.return_type() == Some(ValueType::I32)
}

/// Checks the function signature, `signature`, has the correct type for the
/// `__veracruz_hcall_read_input()` function.  This is:
///
/// ```C
/// enum veracruz_status_t __veracruz_hcall_read_input(uint32_t ix, uint8_t* buffer, uint32_t sz)
/// ```
#[inline]
fn check_read_input_signature(signature: &Signature) -> bool {
    signature.params() == [ValueType::I32, ValueType::I32, ValueType::I32]
        && signature.return_type() == Some(ValueType::I32)
}

/// Checks the function signature, `signature`, has the correct type for the
/// `__veracruz_hcall_write_output()` function.  This is:
///
/// ```C
/// enum veracruz_status_t __veracruz_hcall_write_output(uint8_t* buffer, uint32_t sz);
/// ```
#[inline]
fn check_write_output_signature(signature: &Signature) -> bool {
    signature.params() == [ValueType::I32, ValueType::I32]
        && signature.return_type() == Some(ValueType::I32)
}

/// Checks the function signature, `signature`, has the correct type for the
/// `__veracruz_hcall_getrandom()` function.  This is:
///
/// ```C
/// enum veracruz_status_t __veracruz_hcall_getrandom(uint8_t* buffer, uint32_t sz);
/// ```
#[inline]
fn check_getrandom_signature(signature: &Signature) -> bool {
    signature.params() == [ValueType::I32, ValueType::I32]
        && signature.return_type() == Some(ValueType::I32)
}

/// Checks the function signature `signature` has the correct type for the
/// `__veracruz_hcall_previous_result_size()` function.  This is:
///
///     enum veracruz_status_t __veracruz_hcall_previous_result_size(uint8_t* buffer)
#[inline]
fn check_previous_result_size_signature(signature: &Signature) -> bool {
    signature.params() == [ValueType::I32] && signature.return_type() == Some(ValueType::I32)
}

/// Checks the function signature `signature` has the correct type for the
/// `__veracruz_hcall_has_previous_result()` function.  This is:
///
///     enum veracruz_status_t __veracruz_hcall_has_previous_result(uint8_t* buffer)
#[inline]
fn check_has_previous_result_signature(signature: &Signature) -> bool {
    signature.params() == [ValueType::I32] && signature.return_type() == Some(ValueType::I32)
}

/// Checks the function signature `signature` has the correct type for the
/// `__veracruz_hcall_stream_count()` function.  This is:
///
/// ```C
///     uint32_t __veracruz_hcall_stream_count(void)
/// ```
///
#[inline]
fn check_stream_count_signature(signature: &Signature) -> bool {
    signature.params() == [ValueType::I32] && signature.return_type() == Some(ValueType::I32)
}

/// Checks the function signature `signature` has the correct type for the
/// `__veracruz_hcall_stream_size()` function.  This is:
///
/// ```C
///     enum veracruz_status_t __veracruz_hcall_stream_size(uint32_t ix, uint32_t *sz)
/// ```
#[inline]
fn check_stream_size_signature(signature: &Signature) -> bool {
    signature.params() == [ValueType::I32, ValueType::I32]
        && signature.return_type() == Some(ValueType::I32)
}

/// Checks the function signature `signature` has the correct type for the
/// `__veracruz_hcall_read_stream()` function.  This is:
///
/// ```C
///     enum veracruz_status_t __veracruz_hcall_read_stream(uint32_t ix, uint8_t* buffer, uint32_t sz)
/// ```
#[inline]
fn check_read_stream_signature(signature: &Signature) -> bool {
    signature.params() == [ValueType::I32, ValueType::I32, ValueType::I32]
        && signature.return_type() == Some(ValueType::I32)
}

/// Checks the function signature `signature` has the correct type for the
/// `__veracruz_hcall_read_previous_result()` function.  This is:
///
/// ```C
///     enum veracruz_status_t __veracruz_hcall_read_previous_result(uint8_t* buffer, uint32_t sz)
/// ```
#[inline]
fn check_read_previous_result_signature(signature: &Signature) -> bool {
    signature.params() == [ValueType::I32, ValueType::I32]
        && signature.return_type() == Some(ValueType::I32)
}

/// Checks the function signature, `signature`, has the correct type for the
/// H-call coded by `index`.
fn check_signature(index: usize, signature: &Signature) -> bool {
    match index {
        HCALL_INPUT_COUNT_CODE => check_input_count_signature(signature),
        HCALL_INPUT_SIZE_CODE => check_input_size_signature(signature),
        HCALL_READ_INPUT_CODE => check_read_input_signature(signature),
        HCALL_WRITE_OUTPUT_CODE => check_write_output_signature(signature),
        HCALL_GETRANDOM_CODE => check_getrandom_signature(signature),
        HCALL_READ_PREVIOUS_RESULT_CODE => check_read_previous_result_signature(signature),
        HCALL_PREVIOUS_RESULT_SIZE_CODE => check_previous_result_size_signature(signature),
        HCALL_HAS_PREVIOUS_RESULT_CODE => check_has_previous_result_signature(signature),
        HCALL_STREAM_COUNT_CODE => check_stream_count_signature(signature),
        HCALL_STREAM_SIZE_CODE => check_stream_size_signature(signature),
        HCALL_READ_STREAM_CODE => check_read_stream_signature(signature),
        _otherwise => false,
    }
}

////////////////////////////////////////////////////////////////////////////////
// Finding important module exports.
////////////////////////////////////////////////////////////////////////////////

/// Checks the signature of the module's entry point, `signature`, against the
/// templates described above for the `EntrySignature` enum type, and returns
/// an instance of that type as appropriate.
fn check_main_signature(signature: &Signature) -> EntrySignature {
    let params = signature.params();
    let return_type = signature.return_type();

    if params == [] && return_type == Some(ValueType::I32) {
        EntrySignature::NoParameters
    } else if params == [ValueType::I32, ValueType::I32] && return_type == Some(ValueType::I32) {
        EntrySignature::ArgvAndArgc
    } else {
        EntrySignature::NoEntryFound
    }
}

/// Finds the entry point of the WASM module, `module`, and extracts its
/// signature template.  If no entry is found returns
/// `EntrySignature::NoEntryFound`.
fn check_main(module: &ModuleInstance) -> EntrySignature {
    match module.export_by_name(ENTRY_POINT_NAME) {
        Some(ExternVal::Func(funcref)) => check_main_signature(&funcref.signature()),
        _otherwise => EntrySignature::NoEntryFound,
    }
}

/// Finds the linear memory of the WASM module, `module`, and returns it,
/// otherwise creating a fatal host error that will kill the Veracruz instance.
fn get_module_memory(module: &ModuleRef) -> Result<MemoryRef, HostProvisioningError> {
    match module.export_by_name(LINEAR_MEMORY_NAME) {
        Some(ExternVal::Memory(memoryref)) => Ok(memoryref),
        _otherwise => Err(HostProvisioningError::NoMemoryRegistered),
    }
}

////////////////////////////////////////////////////////////////////////////////
// The H-call interface.
////////////////////////////////////////////////////////////////////////////////

impl ModuleImportResolver for WasmiHostProvisioningState {
    /// "Resolves" a H-call by translating from a H-call name to the
    /// corresponding H-call code, and dispatching appropriately.
    fn resolve_func(&self, field_name: &str, signature: &Signature) -> Result<FuncRef, Error> {
        let index = match field_name {
            HCALL_INPUT_COUNT_NAME => HCALL_INPUT_COUNT_CODE,
            HCALL_INPUT_SIZE_NAME => HCALL_INPUT_SIZE_CODE,
            HCALL_READ_INPUT_NAME => HCALL_READ_INPUT_CODE,
            HCALL_WRITE_OUTPUT_NAME => HCALL_WRITE_OUTPUT_CODE,
            HCALL_GETRANDOM_NAME => HCALL_GETRANDOM_CODE,
            HCALL_READ_PREVIOUS_RESULT_NAME => HCALL_READ_PREVIOUS_RESULT_CODE,
            HCALL_HAS_PREVIOUS_RESULT_NAME => HCALL_HAS_PREVIOUS_RESULT_CODE,
            HCALL_PREVIOUS_RESULT_SIZE_NAME => HCALL_PREVIOUS_RESULT_SIZE_CODE,
            HCALL_STREAM_COUNT_NAME => HCALL_STREAM_COUNT_CODE,
            HCALL_STREAM_SIZE_NAME => HCALL_STREAM_SIZE_CODE,
            HCALL_READ_STREAM_NAME => HCALL_READ_STREAM_CODE,
            otherwise => {
                return Err(Error::Instantiation(format!(
                    "Unknown function export '{}' with signature '{:?}'.",
                    otherwise, signature
                )));
            }
        };

        if !check_signature(index, signature) {
            Err(Error::Instantiation(format!(
                "Function export '{}' has a mismatched signature '{:?}'.",
                field_name, signature
            )))
        } else {
            Ok(FuncInstance::alloc_host(signature.clone(), index))
        }
    }

    fn resolve_global(
        &self,
        field_name: &str,
        _descriptor: &GlobalDescriptor,
    ) -> Result<GlobalRef, Error> {
        Err(Error::Instantiation(field_name.to_string()))
    }

    fn resolve_memory(
        &self,
        field_name: &str,
        _descriptor: &MemoryDescriptor,
    ) -> Result<MemoryRef, Error> {
        Err(Error::Instantiation(field_name.to_string()))
    }

    fn resolve_table(
        &self,
        field_name: &str,
        _descriptor: &TableDescriptor,
    ) -> Result<TableRef, Error> {
        Err(Error::Instantiation(field_name.to_string()))
    }
}

impl Externals for WasmiHostProvisioningState {
    /// Dispatcher for H-calls: checks the H-call code (`index`) and calls an
    /// appropriate H-call specific function based on that index, passing the
    /// runtime arguments, `args`, passed by the WASM program to the
    /// implementation.
    ///
    /// **NOTE**: the `&mut self` argument is ignored here, and all H-call
    /// implementations are invoked on the global host provisioning state
    /// instead.
    fn invoke_index(
        &mut self,
        index: usize,
        args: RuntimeArgs,
    ) -> Result<Option<RuntimeValue>, Trap> {
        let result = match index {
            HCALL_WRITE_OUTPUT_CODE => self.write_output(args),
            HCALL_INPUT_COUNT_CODE => self.input_count(args),
            HCALL_INPUT_SIZE_CODE => self.input_size(args),
            HCALL_READ_INPUT_CODE => self.read_input(args),
            HCALL_GETRANDOM_CODE => self.get_random(args),
            HCALL_STREAM_COUNT_CODE => self.stream_count(args),
            HCALL_STREAM_SIZE_CODE => self.stream_size(args),
            HCALL_READ_STREAM_CODE => self.read_stream(args),
            HCALL_PREVIOUS_RESULT_SIZE_CODE => self.previous_result_size(args),
            HCALL_HAS_PREVIOUS_RESULT_CODE => self.has_previous_result(args),
            HCALL_READ_PREVIOUS_RESULT_CODE => self.previous_result(args),
            otherwise => {
                return mk_host_trap(FatalEngineError::UnknownHostFunction { index: otherwise })
            }
        };
        match result {
            Ok(return_code) => mk_error_code(return_code),
            Err(host_trap) => mk_host_trap(host_trap),
        }
    }
}

/// Functionality of the `WasmiHostProvisioningState` type that relies on it
/// satisfying the `Externals` and `ModuleImportResolver` constraints.
impl WasmiHostProvisioningState {
    /// Creates a new initial `HostProvisioningState`.
    pub fn new(vfs: Arc<Mutex<VFS>>) -> Self {
        Self {
            vfs,
            program: Principal::NoCap,
            program_module: None,
            memory: None,
        }
    }

    /// Returns an optional reference to the WASM program module.
    #[inline]
    pub(crate) fn get_program(&self) -> Option<&ModuleRef> {
        self.program_module.as_ref()
    }

    /// Returns an optional reference to the WASM program's heap.
    #[inline]
    pub(crate) fn get_memory(&self) -> Option<&MemoryRef> {
        self.memory.as_ref()
    }

    /// Loads a compiled program into the host state.  Tries to parse `buffer`
    /// to obtain a WASM `Module` struct.  Returns an appropriate error if this
    /// fails.
    ///
    /// The provisioning process must be in the `LifecycleState::Initial` state
    /// otherwise an error is returned.  Progresses the provisioning process to
    /// the state `LifecycleState::DataSourcesLoading` or
    /// `LifecycleState::ReadyToExecute` on success, depending on how many
    /// sources of input data are expected.
    fn load_program(&mut self, buffer: &[u8]) -> Result<(), HostProvisioningError> {
        let module = Module::from_buffer(buffer)?;
        let env_resolver = wasmi::ImportsBuilder::new().with_resolver("env", self);

        let not_started_module_ref = ModuleInstance::new(&module, &env_resolver)?;
        if not_started_module_ref.has_start() {
            return Err(HostProvisioningError::InvalidWASMModule);
        }

        let module_ref = not_started_module_ref.assert_no_start();

        let linear_memory = get_module_memory(&module_ref)?;
        self.program_module = Some(module_ref);
        self.memory = Some(linear_memory);
        Ok(())
    }

    /// The WASMI implementation of `__veracruz_hcall_write_output()`.
    fn write_output(&mut self, args: RuntimeArgs) -> HCallError {
        if args.len() != 2 {
            return Err(FatalEngineError::BadArgumentsToHostFunction {
                function_name: HCALL_GETRANDOM_NAME.to_string(),
            });
        }

        let address: u32 = args.nth(0);
        let size: u32 = args.nth(1);

        match self.get_memory() {
            None => Err(FatalEngineError::NoMemoryRegistered),
            Some(memory) => match memory.get(address, size as usize) {
                Err(_err) => Err(FatalEngineError::MemoryReadFailed {
                    memory_address: address as usize,
                    bytes_to_be_read: size as usize,
                }),
                Ok(bytes) => {
                    self.write_file(&self.program.clone(), "output", &bytes)?;
                    Ok(EngineReturnCode::Success)
                }
            },
        }
    }

    /// The WASMI implementation of `__veracruz_hcall_input_count()`.
    fn input_count(&mut self, args: RuntimeArgs) -> HCallError {
        if args.len() != 1 {
            return Err(FatalEngineError::BadArgumentsToHostFunction {
                function_name: HCALL_INPUT_COUNT_NAME.to_string(),
            });
        }

        let address: u32 = args.nth(0);
        let result: u32 = self.count_file("input")? as u32;

        match self.get_memory() {
            None => Err(FatalEngineError::NoMemoryRegistered),
            Some(memory) => {
                if let Err(_) = memory.set_value(address, result) {
                    return Err(FatalEngineError::MemoryWriteFailed {
                        memory_address: address as usize,
                        bytes_to_be_written: std::mem::size_of::<u32>(),
                    });
                }

                Ok(EngineReturnCode::Success)
            }
        }
    }

    /// The WASMI implementation of `__veracruz_hcall_input_size()`.
    fn input_size(&mut self, args: RuntimeArgs) -> HCallError {
        if args.len() != 2 {
            return Err(FatalEngineError::BadArgumentsToHostFunction {
                function_name: HCALL_INPUT_SIZE_NAME.to_string(),
            });
        }

        let index: u32 = args.nth(0);
        let address: u32 = args.nth(1);

        match self.get_memory() {
            None => Err(FatalEngineError::NoMemoryRegistered),
            Some(memory) => {
                let result = self
                    .read_file(&self.program, &format!("input-{}", index))?
                    .ok_or(format!("File input-{} cannot be found", index))?
                    .len() as u32;
                let result: Vec<u8> = result.to_le_bytes().to_vec();

                if memory.set(address, &result).is_err() {
                    return Err(FatalEngineError::MemoryWriteFailed {
                        memory_address: address as usize,
                        bytes_to_be_written: result.len() as usize,
                    });
                }

                Ok(EngineReturnCode::Success)
            }
        }
    }

    /// The WASMI implementation of `__veracruz_hcall_read_input()`.
    fn read_input(&mut self, args: RuntimeArgs) -> HCallError {
        if args.len() != 3 {
            return Err(FatalEngineError::BadArgumentsToHostFunction {
                function_name: HCALL_READ_INPUT_NAME.to_string(),
            });
        }

        let index: u32 = args.nth(0);
        let address: u32 = args.nth(1);
        let size: u32 = args.nth(2);

        match self.get_memory() {
            None => Err(FatalEngineError::NoMemoryRegistered),
            Some(memory) => {
                let data = self
                    .read_file(&self.program, &format!("input-{}", index))?
                    .ok_or(format!("File input-{} cannot be found", index))?;
                if data.len() > size as usize {
                    return Ok(EngineReturnCode::DataSourceSize);
                }
                if memory.set(address, &data).is_err() {
                    return Err(FatalEngineError::MemoryWriteFailed {
                        memory_address: address as usize,
                        bytes_to_be_written: data.len(),
                    });
                }

                Ok(EngineReturnCode::Success)
            }
        }
    }

    /// The WASMI implementation of `__veracruz_hcall_stream_count()`.
    fn stream_count(&mut self, args: RuntimeArgs) -> HCallError {
        if args.len() != 1 {
            return Err(FatalEngineError::BadArgumentsToHostFunction {
                function_name: HCALL_STREAM_COUNT_NAME.to_string(),
            });
        }

        let address: u32 = args.nth(0);
        let result = self.count_file("stream")? as u32;

        match self.get_memory() {
            None => Err(FatalEngineError::NoMemoryRegistered),
            Some(memory) => {
                if memory.set_value(address, result).is_err() {
                    return Err(FatalEngineError::MemoryWriteFailed {
                        memory_address: address as usize,
                        bytes_to_be_written: std::mem::size_of::<u32>(),
                    });
                }

                Ok(EngineReturnCode::Success)
            }
        }
    }

    /// The WASMI implementation of `__veracruz_hcall_stream_size()`.
    fn stream_size(&mut self, args: RuntimeArgs) -> HCallError {
        if args.len() != 2 {
            return Err(FatalEngineError::BadArgumentsToHostFunction {
                function_name: HCALL_STREAM_SIZE_NAME.to_string(),
            });
        }

        let index: u32 = args.nth(0);
        let address: u32 = args.nth(1);

        match self.get_memory() {
            None => Err(FatalEngineError::NoMemoryRegistered),
            Some(memory) => {
                let result = self
                    .read_file(&self.program, &format!("stream-{}", index))?
                    .ok_or(format!("File input-{} cannot be found", index))?
                    .len() as u32;
                let result: Vec<u8> = result.to_le_bytes().to_vec();

                if memory.set(address, &result).is_err() {
                    return Err(FatalEngineError::MemoryWriteFailed {
                        memory_address: address as usize,
                        bytes_to_be_written: result.len(),
                    });
                }

                Ok(EngineReturnCode::Success)
            }
        }
    }

    /// The WASMI implementation of `__veracruz_hcall_stream_input()`.
    fn read_stream(&mut self, args: RuntimeArgs) -> HCallError {
        if args.len() != 3 {
            return Err(FatalEngineError::BadArgumentsToHostFunction {
                function_name: HCALL_READ_STREAM_NAME.to_string(),
            });
        }

        let index: u32 = args.nth(0);
        let address: u32 = args.nth(1);
        let size: u32 = args.nth(2);

        match self.get_memory() {
            None => Err(FatalEngineError::NoMemoryRegistered),
            Some(memory) => {
                let data = self
                    .read_file(&self.program, &format!("stream-{}", index))?
                    .ok_or(format!("File input-{} cannot be found", index))?;
                if data.len() > size as usize {
                    return Ok(EngineReturnCode::DataSourceSize);
                }
                if memory.set(address, &data).is_err() {
                    return Err(FatalEngineError::MemoryWriteFailed {
                        memory_address: address as usize,
                        bytes_to_be_written: data.len(),
                    });
                }

                Ok(EngineReturnCode::Success)
            }
        }
    }

    /// The WASMI implementation of the `__veracruz_hcall_previous_result_size()`.
    fn previous_result_size(&mut self, args: RuntimeArgs) -> HCallError {
        if args.len() != 1 {
            return Err(FatalEngineError::BadArgumentsToHostFunction {
                function_name: HCALL_PREVIOUS_RESULT_SIZE_NAME.to_string(),
            });
        }

        let address: u32 = args.nth(0);

        match self.get_memory() {
            None => Err(FatalEngineError::NoMemoryRegistered),
            Some(memory) => {
                let result = self
                    .read_file(&self.program, "output")?
                    .unwrap_or(Vec::new());
                let result: Vec<u8> = result.len().to_le_bytes().to_vec();
                if memory.set(address, &result).is_err() {
                    return Err(FatalEngineError::MemoryWriteFailed {
                        memory_address: address as usize,
                        bytes_to_be_written: result.len(),
                    });
                }
                Ok(EngineReturnCode::Success)
            }
        }
    }

    /// The WASMI implementation of the `__veracruz_hcall_read_previous_result()`.
    fn previous_result(&mut self, args: RuntimeArgs) -> HCallError {
        if args.len() != 2 {
            return Err(FatalEngineError::BadArgumentsToHostFunction {
                function_name: HCALL_READ_PREVIOUS_RESULT_NAME.to_string(),
            });
        }

        let address: u32 = args.nth(0);
        let size: u32 = args.nth(1);

        match self.get_memory() {
            None => Err(FatalEngineError::NoMemoryRegistered),
            Some(memory) => {
                let previous_result = self
                    .read_file(&self.program, "output")?
                    .unwrap_or(Vec::new());

                if previous_result.len() > size as usize {
                    return Ok(EngineReturnCode::PreviousResultSize);
                }

                if memory.set(address, &previous_result).is_err() {
                    return Err(FatalEngineError::MemoryWriteFailed {
                        memory_address: address as usize,
                        bytes_to_be_written: previous_result.len(),
                    });
                }
                Ok(EngineReturnCode::Success)
            }
        }
    }

    /// The WASMI implementation of the `__veracruz_hcall_has_previous_result()`.
    fn has_previous_result(&mut self, args: RuntimeArgs) -> HCallError {
        if args.len() != 1 {
            return Err(FatalEngineError::BadArgumentsToHostFunction {
                function_name: HCALL_HAS_PREVIOUS_RESULT_NAME.to_string(),
            });
        }

        let address: u32 = args.nth(0);

        match self.get_memory() {
            None => Err(FatalEngineError::NoMemoryRegistered),
            Some(memory) => {
                let previous_result = self.read_file(&self.program, "output")?;
                let flag: u32 = match previous_result {
                    Some(_) => 1,
                    None => 0,
                };
                let result: Vec<u8> = flag.to_le_bytes().to_vec();

                if memory.set(address, &result).is_err() {
                    return Err(FatalEngineError::MemoryWriteFailed {
                        memory_address: address as usize,
                        bytes_to_be_written: result.len(),
                    });
                }
                Ok(EngineReturnCode::Success)
            }
        }
    }

    /// The WASMI implementation of `__veracruz_hcall_getrandom()`.
    fn get_random(&mut self, args: RuntimeArgs) -> HCallError {
        if args.len() != 2 {
            return Err(FatalEngineError::BadArgumentsToHostFunction {
                function_name: HCALL_GETRANDOM_NAME.to_string(),
            });
        }

        let address: u32 = args.nth(0);
        let size: u32 = args.nth(1);
        let mut buffer = vec![0; size as usize];

        match self.get_memory() {
            None => Err(FatalEngineError::NoMemoryRegistered),
            Some(memory) => match getrandom(&mut buffer) {
                result::Result::Success => {
                    if memory.set(address, &buffer).is_err() {
                        return Err(FatalEngineError::MemoryWriteFailed {
                            memory_address: address as usize,
                            bytes_to_be_written: size as usize,
                        });
                    }

                    Ok(EngineReturnCode::Success)
                }
                result::Result::Unavailable => Ok(EngineReturnCode::ServiceUnavailable),
                result::Result::UnknownError => Ok(EngineReturnCode::Generic),
            },
        }
    }

    /// Invokes an exported entry point function with a given name,
    /// `export_name`, in the WASM program provisioned into the Veracruz host
    /// state.
    ///
    /// TODO: some awkwardness with the borrow checker here --- revisit.
    fn invoke_export(&mut self, export_name: &str) -> Result<Option<RuntimeValue>, Error> {
        // Eliminate this .cloned() call, if possible
        let (not_started, program_arguments) = match self.get_program().cloned() {
            None => {
                return Err(Error::Host(Box::new(
                    FatalEngineError::NoProgramModuleRegistered,
                )))
            }
            Some(not_started) => match check_main(&not_started) {
                EntrySignature::NoEntryFound => {
                    return Err(Error::Host(Box::new(FatalEngineError::NoProgramEntryPoint)))
                }
                EntrySignature::ArgvAndArgc => (
                    not_started,
                    vec![RuntimeValue::I32(0), RuntimeValue::I32(0)],
                ),
                EntrySignature::NoParameters => (not_started, Vec::new()),
            },
        };

        not_started.invoke_export(export_name, &program_arguments, self)
    }

    /// ExecutionEngine wrapper of append_file implementation in WasmiHostProvisioningState.
    #[inline]
    fn append_file(
        &mut self,
        client_id: &Principal,
        file_name: &str,
        data: &[u8],
    ) -> Result<(), HostProvisioningError> {
        self.vfs.lock()?.append(client_id, file_name, data)?;
        Ok(())
    }

    /// ExecutionEngine wrapper of write_file implementation in WasmiHostProvisioningState.
    #[inline]
    fn write_file(
        &mut self,
        client_id: &Principal,
        file_name: &str,
        data: &[u8],
    ) -> Result<(), HostProvisioningError> {
        self.vfs.lock()?.write(client_id, file_name, data)?;
        Ok(())
    }

    /// ExecutionEngine wrapper of read_file implementation in WasmiHostProvisioningState.
    #[inline]
    fn read_file(
        &self,
        client_id: &Principal,
        file_name: &str,
    ) -> Result<Option<Vec<u8>>, HostProvisioningError> {
        Ok(self.vfs.lock()?.read(client_id, file_name)?)
    }

    #[inline]
    fn count_file(&self, prefix: &str) -> Result<u64, HostProvisioningError> {
        Ok(self.vfs.lock()?.count(prefix)?)
    }
}

/// The `WasmiHostProvisioningState` implements everything needed to create a
/// compliant instance of `ExecutionEngine`.
impl ExecutionEngine for WasmiHostProvisioningState {
    /// Executes the entry point of the WASM program provisioned into the
    /// Veracruz host.
    ///
    /// Returns an error if no program is registered, the program registered
    /// does not have an appropriate entry point, or if the machine is not
    /// in the `LifecycleState::ReadyToExecute` state prior to being called.
    ///
    /// Also returns an error if the WASM program or the Veracruz instance
    /// create a runtime trap during program execution (e.g. if the program
    /// executes an abort instruction, or passes bad parameters to the Veracruz
    /// host).
    ///
    /// Otherwise, returns the return value of the entry point function of the
    /// program, along with a host state capturing the result of the program's
    /// execution.
    fn invoke_entry_point(
        &mut self,
        file_name: &str,
    ) -> Result<EngineReturnCode, FatalEngineError> {
        let program = self
            .read_file(&Principal::InternalSuperUser, file_name)?
            .ok_or(format!("Program file {} cannot be found.", file_name))?;
        self.load_program(program.as_slice())?;
        self.program = Principal::Program(file_name.to_string());

        match self.invoke_export(ENTRY_POINT_NAME) {
            Ok(Some(RuntimeValue::I32(return_code))) => EngineReturnCode::try_from(return_code),
            Ok(_) => Err(FatalEngineError::ReturnedCodeError),
            Err(Error::Trap(trap)) => Err(FatalEngineError::WASMITrapError(trap)),
            Err(err) => Err(FatalEngineError::WASMIError(err)),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Utility functions.
////////////////////////////////////////////////////////////////////////////////

/// Utility function which simplifies building a serialized Veracruz error code
/// to be passed back to the running WASM program executing on the WASMI engine.
#[inline]
pub(crate) fn mk_error_code<T>(e: EngineReturnCode) -> Result<Option<RuntimeValue>, T> {
    Ok(Some(RuntimeValue::I32(e.into())))
}

/// Utility function which simplifies building a Veracruz host trap.
#[inline]
pub(crate) fn mk_host_trap<T>(trap: FatalEngineError) -> Result<T, Trap> {
    Err(Trap::new(TrapKind::Host(Box::new(trap))))
}