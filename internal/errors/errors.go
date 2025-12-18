package errors

import (
	"fmt"
)

// Exit codes
const (
	ExitSuccess         = 0
	ExitGeneralError    = 1
	ExitSecurityBlock   = 2
	ExitConfigError     = 3
	ExitContainerError  = 4
	ExitNetworkError    = 5
	ExitScannerError    = 6
	ExitManifestError   = 7
	ExitUserAbort       = 130
)

// SnapemError is the base error type for snapem
type SnapemError struct {
	Code    int
	Message string
	Cause   error
	Details map[string]interface{}
}

func (e *SnapemError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *SnapemError) Unwrap() error {
	return e.Cause
}

// ExitCode returns the exit code for this error
func (e *SnapemError) ExitCode() int {
	return e.Code
}

// New creates a new SnapemError
func New(code int, message string) *SnapemError {
	return &SnapemError{
		Code:    code,
		Message: message,
		Details: make(map[string]interface{}),
	}
}

// Wrap wraps an existing error
func Wrap(code int, message string, cause error) *SnapemError {
	return &SnapemError{
		Code:    code,
		Message: message,
		Cause:   cause,
		Details: make(map[string]interface{}),
	}
}

// WithDetail adds a detail to the error
func (e *SnapemError) WithDetail(key string, value interface{}) *SnapemError {
	e.Details[key] = value
	return e
}

// Convenience constructors

// SecurityBlockError creates an error for blocked security threats
func SecurityBlockError(message string) *SnapemError {
	return New(ExitSecurityBlock, message)
}

// ContainerNotAvailableError creates an error when container runtime is missing
func ContainerNotAvailableError() *SnapemError {
	return New(ExitContainerError, "Apple container runtime not available").
		WithDetail("help", "Install with: brew install --cask container")
}

// ContainerError creates an error for container execution failures
func ContainerError(cause error) *SnapemError {
	return Wrap(ExitContainerError, "container execution failed", cause)
}

// ConfigError creates an error for configuration issues
func ConfigError(message string) *SnapemError {
	return New(ExitConfigError, message)
}

// ManifestError creates an error for manifest parsing issues
func ManifestError(message string, cause error) *SnapemError {
	return Wrap(ExitManifestError, message, cause)
}

// ScannerError creates an error for scanner failures
func ScannerError(scanner string, cause error) *SnapemError {
	return Wrap(ExitScannerError, fmt.Sprintf("%s scanner failed", scanner), cause)
}

// NetworkError creates an error for network/API failures
func NetworkError(service string, cause error) *SnapemError {
	return Wrap(ExitNetworkError, fmt.Sprintf("failed to connect to %s", service), cause)
}

// UserAbortError creates an error when user cancels operation
func UserAbortError() *SnapemError {
	return New(ExitUserAbort, "operation cancelled by user")
}
