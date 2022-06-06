<?php

namespace App\HelperService;

use \Illuminate\Http\JsonResponse;

class Helpers
{
    public function response(bool $isSuccess, string $report, $details, $errors, $responseCode): JsonResponse
    {
        return response()->json([
            'success' => $isSuccess,
            'responseCode' => $responseCode,
            'errors' => $errors,
            'report' => $report,
            'details' => $details
        ], $responseCode, [], JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT);
    }
}
