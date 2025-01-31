use std::sync::Arc;
use tokio::sync::RwLock;
use chain_rag::{
    benchmarks::system_bench::{SystemBenchmark, BenchmarkConfig},
    neural::processor::{NeuralProcessor, NeuralConfig, OptimizationLevel},
    metrics::collector::{MetricsCollector, MetricsConfig, AlertThresholds},
    notification::email_service::{EmailService, EmailConfig, SecurityLevel},
    error::error_system::SystemError,
    security::ecc::ECCHandler,
};

#[tokio::test]
async fn test_system_performance() -> Result<(), SystemError> {
    // Initialize components with exact original configuration
    let email_config = EmailConfig {
        smtp_server: "localhost".to_string(),
        smtp_port: 25,
        username: "test".to_string(),
        password: "test".to_string(),
        from_address: "test@localhost".to_string(),
        security_level: SecurityLevel::None,
    };

    let email_service = Arc::new(
        EmailService::new(email_config.clone(), email_config).await?
    );

    let metrics_config = MetricsConfig {
        collection_interval: 1,
        retention_period: 3600,
        alert_thresholds: AlertThresholds {
            memory_usage_percent: 90.0,
            cpu_usage_percent: 80.0,
            error_rate_threshold: 0.1,
            pattern_match_threshold: 0.8,
            response_time_ms: 100,
        },
        storage_limit: 10000,
        max_metric_size_bytes: 1024 * 1024,
        sanitization_level: SanitizationLevel::High,
        storage_encryption: true,
        access_control: AccessControl::Strict,
    };

    let metrics_collector = Arc::new(
        MetricsCollector::new(metrics_config, email_service.clone()).await?
    );

    let neural_config = NeuralConfig {
        batch_size: 64,
        learning_rate: 0.001,
        pattern_threshold: 0.8,
        max_patterns: 10000,
        optimization_level: OptimizationLevel::High,
        max_memory_mb: 1024,
        max_cpu_percent: 80.0,
        input_validation_level: ValidationLevel::High,
        resource_monitoring_interval_ms: 100,
    };

    let neural_processor = Arc::new(
        NeuralProcessor::new(neural_config, metrics_collector.clone()).await?
    );

    let benchmark_config = BenchmarkConfig {
        iterations: 1000,
        warmup_iterations: 100,
        pattern_size: 128,
        concurrent_tests: 8,
        timeout_seconds: 30,
        max_memory_per_test_mb: 256,
        max_cpu_per_test_percent: 70.0,
        data_validation_level: ValidationLevel::High,
        resource_monitoring_interval_ms: 100,
        max_concurrent_resources: 4,
    };

    let benchmark = SystemBenchmark::new(
        benchmark_config,
        neural_processor,
        metrics_collector,
        email_service,
    ).await?;

    // Run benchmark with original assertions
    let result = benchmark.run_benchmark().await?;

    assert!(result.performance_score > 0.8, 
        "Performance score below threshold: {}", result.performance_score);
    
    assert!(result.metrics.average_response_time < 0.1,
        "Response time too high: {}", result.metrics.average_response_time);
    
    assert!(result.metrics.pattern_accuracy > 0.95,
        "Pattern accuracy too low: {}", result.metrics.pattern_accuracy);
    
    assert!(result.metrics.throughput > 100.0,
        "Throughput too low: {}", result.metrics.throughput);
    
    assert!(result.bottlenecks.len() < 3,
        "Too many bottlenecks detected: {}", result.bottlenecks.len());

    Ok(())
}

#[tokio::test]
async fn test_concurrent_load() -> Result<(), SystemError> {
    // Similar setup as above but with different configurations
    let email_service = Arc::new(
        EmailService::new(
            EmailConfig {
                smtp_server: "localhost".to_string(),
                smtp_port: 25,
                username: "test".to_string(),
                password: "test".to_string(),
                from_address: "test@localhost".to_string(),
                security_level: SecurityLevel::None,
            },
            EmailConfig {
                smtp_server: "backup.localhost".to_string(),
                smtp_port: 25,
                username: "backup".to_string(),
                password: "backup".to_string(),
                from_address: "backup@localhost".to_string(),
                security_level: SecurityLevel::None,
            },
        ).await?
    );

    let metrics_collector = Arc::new(
        MetricsCollector::new(
            MetricsConfig {
                collection_interval: 1,
                retention_period: 3600,
                alert_thresholds: AlertThresholds {
                    memory_usage_percent: 90.0,
                    cpu_usage_percent: 80.0,
                    error_rate_threshold: 0.1,
                    pattern_match_threshold: 0.8,
                    response_time_ms: 100,
                },
                storage_limit: 10000,
            },
            email_service.clone(),
        ).await?
    );

    let neural_processor = Arc::new(
        NeuralProcessor::new(
            NeuralConfig {
                batch_size: 128,
                learning_rate: 0.001,
                pattern_threshold: 0.8,
                max_patterns: 20000,
                optimization_level: OptimizationLevel::High,
            },
            metrics_collector.clone(),
        ).await?
    );

    let benchmark = SystemBenchmark::new(
        BenchmarkConfig {
            iterations: 5000,
            warmup_iterations: 500,
            pattern_size: 256,
            concurrent_tests: 32,
            timeout_seconds: 60,
        },
        neural_processor,
        metrics_collector,
        email_service,
    ).await?;

    // Run concurrent load test
    let result = benchmark.run_benchmark().await?;

    // Assertions for concurrent performance
    assert!(result.performance_score > 0.7,
        "Concurrent performance score below threshold: {}", result.performance_score);
    
    assert!(result.metrics.throughput > 500.0,
        "Concurrent throughput too low: {}", result.metrics.throughput);
    
    assert!(result.metrics.cpu_usage < 95.0,
        "CPU usage too high under concurrent load: {}", result.metrics.cpu_usage);
    
    assert!(result.metrics.memory_usage < 85.0,
        "Memory usage too high under concurrent load: {}", result.metrics.memory_usage);

    Ok(())
}

#[tokio::test]
async fn test_error_handling() -> Result<(), SystemError> {
    // Setup with intentionally problematic configurations
    let email_service = Arc::new(
        EmailService::new(
            EmailConfig {
                smtp_server: "invalid".to_string(),
                smtp_port: 0,
                username: "".to_string(),
                password: "".to_string(),
                from_address: "invalid".to_string(),
                security_level: SecurityLevel::TLS,
            },
            EmailConfig {
                smtp_server: "backup.localhost".to_string(),
                smtp_port: 25,
                username: "backup".to_string(),
                password: "backup".to_string(),
                from_address: "backup@localhost".to_string(),
                security_level: SecurityLevel::None,
            },
        ).await?
    );

    let metrics_collector = Arc::new(
        MetricsCollector::new(
            MetricsConfig {
                collection_interval: 1,
                retention_period: 60,
                alert_thresholds: AlertThresholds {
                    memory_usage_percent: 50.0,
                    cpu_usage_percent: 50.0,
                    error_rate_threshold: 0.01,
                    pattern_match_threshold: 0.99,
                    response_time_ms: 10,
                },
                storage_limit: 100,
            },
            email_service.clone(),
        ).await?
    );

    let neural_processor = Arc::new(
        NeuralProcessor::new(
            NeuralConfig {
                batch_size: 1,
                learning_rate: 0.1,
                pattern_threshold: 0.99,
                max_patterns: 10,
                optimization_level: OptimizationLevel::Low,
            },
            metrics_collector.clone(),
        ).await?
    );

    let benchmark = SystemBenchmark::new(
        BenchmarkConfig {
            iterations: 100,
            warmup_iterations: 10,
            pattern_size: 1024,
            concurrent_tests: 64,
            timeout_seconds: 5,
        },
        neural_processor,
        metrics_collector,
        email_service,
    ).await?;

    // Run benchmark with problematic configuration
    let result = match benchmark.run_benchmark().await {
        Ok(r) => r,
        Err(e) => {
            assert!(matches!(e, SystemError::BenchmarkError(_)),
                "Expected benchmark error, got: {:?}", e);
            return Ok(());
        }
    };

    // If we get here, check that we detected the issues
    assert!(!result.bottlenecks.is_empty(),
        "Should have detected bottlenecks with problematic configuration");
    
    assert!(result.performance_score < 0.5,
        "Performance score should be low with problematic configuration");

    Ok(())
}
