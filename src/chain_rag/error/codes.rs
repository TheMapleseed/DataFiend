pub enum NumericErrorCode {
    // VM Control Errors (1000-1999)
    VMInitializationError = 1000,
    VMTerminationError = 1001,
    VMStateError = 1002,
    VMMemoryError = 1003,
    
    // Signal Transmission Errors (2000-2999)
    SignalTransmissionFailed = 2000,
    SignalValidationFailed = 2001,
    SignalTimeoutError = 2002,
    
    // Pattern Processing Errors (3000-3999)
    PatternValidationError = 3000,
    PatternProcessingError = 3001,
    PatternStorageError = 3002,
    
    // ... other original error codes ...
} 
