<?php

namespace App\Kbiz;

enum ApprovalStatus: string
{
    case Pending = 'pending';
    case Approved = 'approved';
    case Rejected = 'rejected';
}
