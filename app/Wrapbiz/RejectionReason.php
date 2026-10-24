<?php

namespace App\Wrapbiz;

/**
 * Business errors from the registration functions; the whole call is rolled
 * back for every one of them. All but InvalidInput are raised by name
 * (SQLSTATE P0001); InvalidInput is any check-constraint violation (SQLSTATE
 * 23514) on the other parameters. StatesBudgetExhausted comes only from
 * registration_account_states(), the user, endpoint and account reasons only
 * from register_connection().
 */
enum RejectionReason: string
{
    case CodeUnusable = 'register_code_unusable';
    case InvalidAccounts = 'invalid_accounts';
    case UserAlreadyRegistered = 'user_already_registered';
    case AccountAlreadyRegistered = 'account_already_registered';
    case EndpointConflict = 'endpoint_conflict';
    case EndpointUrlLocked = 'endpoint_url_locked';
    case EndpointDisabled = 'endpoint_disabled';
    case StatesBudgetExhausted = 'states_budget_exhausted';
    case InvalidInput = 'check_violation';
}
