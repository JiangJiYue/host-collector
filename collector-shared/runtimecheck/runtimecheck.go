package runtimecheck

import (
	"fmt"

	"collector-shared/contracts"
)

type Requirement string

const (
	RequirementRoot          Requirement = "root"
	RequirementAdministrator Requirement = "administrator"
)

type Reason string

const (
	ReasonRootPresent           Reason = "root_present"
	ReasonRootRequired          Reason = "root_required"
	ReasonAdministratorPresent  Reason = "administrator_present"
	ReasonAdministratorRequired Reason = "administrator_required"
)

type Result struct {
	Allowed     bool
	Requirement Requirement
	Reason      Reason
	Message     string
	Evidence    string
}

func RequireRoot(uid int) Result {
	if uid == 0 {
		return Result{
			Allowed:     true,
			Requirement: RequirementRoot,
			Reason:      ReasonRootPresent,
			Evidence:    "uid=0",
		}
	}
	return Result{
		Allowed:     false,
		Requirement: RequirementRoot,
		Reason:      ReasonRootRequired,
		Message:     "linux-host-collector scan requires root privileges (uid=0)",
		Evidence:    fmt.Sprintf("uid=%d", uid),
	}
}

func RequireAdministrator(isAdministrator bool) Result {
	if isAdministrator {
		return Result{
			Allowed:     true,
			Requirement: RequirementAdministrator,
			Reason:      ReasonAdministratorPresent,
			Evidence:    "administrator",
		}
	}
	return Result{
		Allowed:     false,
		Requirement: RequirementAdministrator,
		Reason:      ReasonAdministratorRequired,
		Message:     "windows-host-collector scan requires Administrator privileges",
		Evidence:    "not_elevated",
	}
}

func (r Result) Err() error {
	if r.Allowed {
		return nil
	}
	message := r.Message
	if message == "" {
		message = string(r.Reason)
	}
	return contracts.NewCollectorError(contracts.ErrorPermissionDenied, message, nil)
}
