package contracts

type ErrorCode string

const (
	ErrorUnknown           ErrorCode = "unknown"
	ErrorCapabilityMissing ErrorCode = "capability_missing"
	ErrorPermissionDenied  ErrorCode = "permission_denied"
	ErrorTimeout           ErrorCode = "timeout"
	ErrorCanceled          ErrorCode = "canceled"
	ErrorInvalidPayload    ErrorCode = "invalid_payload"
	ErrorUploadFailed      ErrorCode = "upload_failed"
)

type CollectorError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Cause   error     `json:"-"`
}

func NewCollectorError(code ErrorCode, message string, cause error) *CollectorError {
	return &CollectorError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

func (err *CollectorError) Error() string {
	if err.Cause == nil {
		return string(err.Code) + ": " + err.Message
	}
	return string(err.Code) + ": " + err.Message + ": " + err.Cause.Error()
}

func (err *CollectorError) Unwrap() error {
	return err.Cause
}
