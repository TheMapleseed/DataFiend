pub enum ControlSystemCode {
    // VM State Control (100-199)
    VMInitialize = 100,
    VMPause = 101,
    VMResume = 102,
    VMTerminate = 103,
    VMReset = 104,
    VMSnapshot = 105,
    VMRestore = 106,
    
    // Memory Management (200-299)
    MemoryAlloc = 200,
    MemoryFree = 201,
    MemoryDefrag = 202,
    MemoryCompress = 203,
    MemoryExpand = 204,
    MemoryProtect = 205,
    
    // Pattern Control (300-399)
    PatternLoad = 300,
    PatternUnload = 301,
    PatternOptimize = 302,
    PatternMerge = 303,
    PatternSplit = 304,
    PatternValidate = 305,
    
    // Signal Control (400-499)
    SignalInit = 400,
    SignalRoute = 401,
    SignalProcess = 402,
    SignalTerminate = 403,
    SignalPrioritize = 404,
    SignalBuffer = 405,
    
    // Resource Management (500-599)
    ResourceAlloc = 500,
    ResourceFree = 501,
    ResourceLimit = 502,
    ResourceMonitor = 503,
    ResourceOptimize = 504,
    ResourceRebalance = 505,
    
    // Security Control (600-699)
    SecurityInit = 600,
    SecurityVerify = 601,
    SecurityEncrypt = 602,
    SecurityDecrypt = 603,
    SecurityAudit = 604,
    SecurityLock = 605,
    
    // Error Handling (700-799)
    ErrorCapture = 700,
    ErrorProcess = 701,
    ErrorRecover = 702,
    ErrorLog = 703,
    ErrorNotify = 704,
    ErrorReset = 705,
}

impl ControlSystemCode {
    pub fn is_critical(&self) -> bool {
        matches!(self,
            Self::VMInitialize | 
            Self::VMTerminate |
            Self::MemoryAlloc |
            Self::MemoryFree |
            Self::SecurityInit |
            Self::SecurityVerify |
            Self::ErrorCapture |
            Self::ErrorRecover
        )
    }

    pub fn requires_verification(&self) -> bool {
        matches!(self,
            Self::VMSnapshot |
            Self::VMRestore |
            Self::MemoryProtect |
            Self::PatternValidate |
            Self::SecurityVerify |
            Self::SecurityAudit
        )
    }

    pub fn get_priority(&self) -> u8 {
        match self {
            Self::VMInitialize | Self::VMTerminate => 0,
            Self::SecurityInit | Self::SecurityVerify => 1,
            Self::ErrorCapture | Self::ErrorRecover => 2,
            Self::MemoryAlloc | Self::MemoryFree => 3,
            _ => 4,
        }
    }
} 
