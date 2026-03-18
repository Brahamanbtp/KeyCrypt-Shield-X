# KeyCrypt Shield X API

REST API for encryption, key lifecycle, and security operations.

- Version: `0.1.0`
- Base URL: `http://localhost:8000`

## Authentication

Protected endpoints require:

```http
Authorization: Bearer <token>
```

Use `POST /auth/token` to obtain a JWT.

## Endpoints

### POST /auth/token

- Tags: auth
- Operation ID: `issue_token_auth_token_post`
- Authentication: Not required

Issue Token


#### Request Schema


```json
{
  "properties": {
    "password": {
      "title": "Password",
      "type": "string"
    },
    "username": {
      "title": "Username",
      "type": "string"
    }
  },
  "required": [
    "username",
    "password"
  ],
  "title": "TokenRequest",
  "type": "object"
}
```


#### Response Schemas


Status `200`:

```json
{
  "properties": {
    "access_token": {
      "title": "Access Token",
      "type": "string"
    },
    "expires_at": {
      "title": "Expires At",
      "type": "number"
    },
    "token_type": {
      "default": "bearer",
      "title": "Token Type",
      "type": "string"
    }
  },
  "required": [
    "access_token",
    "expires_at"
  ],
  "title": "TokenResponse",
  "type": "object"
}
```


Status `422`:

```json
{
  "properties": {
    "detail": {
      "items": {
        "properties": {
          "ctx": {
            "title": "Context",
            "type": "object"
          },
          "input": {
            "title": "Input"
          },
          "loc": {
            "items": {
              "type": "string"
            },
            "title": "Location",
            "type": "array"
          },
          "msg": {
            "title": "Message",
            "type": "string"
          },
          "type": {
            "title": "Error Type",
            "type": "string"
          }
        },
        "required": [
          "loc",
          "msg",
          "type"
        ],
        "title": "ValidationError",
        "type": "object"
      },
      "title": "Detail",
      "type": "array"
    }
  },
  "title": "HTTPValidationError",
  "type": "object"
}
```



#### Example Request

```bash
curl -X POST 'http://localhost:8000/auth/token' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "username": "string",
  "password": "string"
}'
```

#### Example Response

```json
{
  "access_token": "string",
  "expires_at": 0.0,
  "token_type": "string"
}
```


### POST /decrypt

- Tags: crypto
- Operation ID: `decrypt_file_decrypt_post`
- Authentication: Required

Decrypt File


#### Request Schema


```json
{
  "properties": {
    "aad": {
      "type": "string"
    },
    "encrypted_file_b64": {
      "title": "Encrypted File B64",
      "type": "string"
    },
    "key_b64": {
      "type": "string"
    },
    "key_id": {
      "type": "string"
    },
    "nonce_b64": {
      "title": "Nonce B64",
      "type": "string"
    }
  },
  "required": [
    "encrypted_file_b64",
    "nonce_b64"
  ],
  "title": "DecryptRequest",
  "type": "object"
}
```


#### Response Schemas


Status `200`:

```json
{
  "properties": {
    "metadata": {
      "additionalProperties": true,
      "title": "Metadata",
      "type": "object"
    },
    "plaintext_b64": {
      "title": "Plaintext B64",
      "type": "string"
    }
  },
  "required": [
    "plaintext_b64",
    "metadata"
  ],
  "title": "DecryptResponse",
  "type": "object"
}
```


Status `422`:

```json
{
  "properties": {
    "detail": {
      "items": {
        "properties": {
          "ctx": {
            "title": "Context",
            "type": "object"
          },
          "input": {
            "title": "Input"
          },
          "loc": {
            "items": {
              "type": "string"
            },
            "title": "Location",
            "type": "array"
          },
          "msg": {
            "title": "Message",
            "type": "string"
          },
          "type": {
            "title": "Error Type",
            "type": "string"
          }
        },
        "required": [
          "loc",
          "msg",
          "type"
        ],
        "title": "ValidationError",
        "type": "object"
      },
      "title": "Detail",
      "type": "array"
    }
  },
  "title": "HTTPValidationError",
  "type": "object"
}
```



#### Example Request

```bash
curl -X POST 'http://localhost:8000/decrypt' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "encrypted_file_b64": "string",
  "key_b64": "string",
  "key_id": "string",
  "nonce_b64": "string",
  "aad": "string"
}'
```

#### Example Response

```json
{
  "metadata": {},
  "plaintext_b64": "string"
}
```


### POST /encrypt

- Tags: crypto
- Operation ID: `encrypt_file_encrypt_post`
- Authentication: Required

Encrypt File


#### Request Schema


```json
{
  "properties": {
    "file": {
      "contentMediaType": "application/octet-stream",
      "title": "File",
      "type": "string"
    }
  },
  "required": [
    "file"
  ],
  "title": "Body_encrypt_file_encrypt_post",
  "type": "object"
}
```


#### Response Schemas


Status `200`:

```json
{
  "properties": {
    "algorithm": {
      "title": "Algorithm",
      "type": "string"
    },
    "encrypted_file_b64": {
      "title": "Encrypted File B64",
      "type": "string"
    },
    "key_id": {
      "type": "string"
    },
    "metadata": {
      "additionalProperties": true,
      "title": "Metadata",
      "type": "object"
    }
  },
  "required": [
    "algorithm",
    "encrypted_file_b64",
    "metadata"
  ],
  "title": "EncryptResponse",
  "type": "object"
}
```


Status `422`:

```json
{
  "properties": {
    "detail": {
      "items": {
        "properties": {
          "ctx": {
            "title": "Context",
            "type": "object"
          },
          "input": {
            "title": "Input"
          },
          "loc": {
            "items": {
              "type": "string"
            },
            "title": "Location",
            "type": "array"
          },
          "msg": {
            "title": "Message",
            "type": "string"
          },
          "type": {
            "title": "Error Type",
            "type": "string"
          }
        },
        "required": [
          "loc",
          "msg",
          "type"
        ],
        "title": "ValidationError",
        "type": "object"
      },
      "title": "Detail",
      "type": "array"
    }
  },
  "title": "HTTPValidationError",
  "type": "object"
}
```



#### Example Request

```bash
curl -X POST 'http://localhost:8000/encrypt' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "file": "string"
}'
```

#### Example Response

```json
{
  "algorithm": "string",
  "encrypted_file_b64": "string",
  "key_id": "string",
  "metadata": {}
}
```


### POST /keys/generate

- Tags: keys
- Operation ID: `generate_key_keys_generate_post`
- Authentication: Required

Generate Key


#### Request Schema


```json
{
  "properties": {
    "algorithm": {
      "default": "AES-256-GCM",
      "minLength": 1,
      "title": "Algorithm",
      "type": "string"
    }
  },
  "title": "GenerateKeyRequest",
  "type": "object"
}
```


#### Response Schemas


Status `200`:

```json
{
  "properties": {
    "algorithm": {
      "title": "Algorithm",
      "type": "string"
    },
    "created_at": {
      "title": "Created At",
      "type": "number"
    },
    "expires_at": {
      "type": "number"
    },
    "key_id": {
      "title": "Key Id",
      "type": "string"
    },
    "public_metadata": {
      "additionalProperties": true,
      "title": "Public Metadata",
      "type": "object"
    }
  },
  "required": [
    "key_id",
    "algorithm",
    "created_at",
    "expires_at",
    "public_metadata"
  ],
  "title": "GenerateKeyResponse",
  "type": "object"
}
```


Status `422`:

```json
{
  "properties": {
    "detail": {
      "items": {
        "properties": {
          "ctx": {
            "title": "Context",
            "type": "object"
          },
          "input": {
            "title": "Input"
          },
          "loc": {
            "items": {
              "type": "string"
            },
            "title": "Location",
            "type": "array"
          },
          "msg": {
            "title": "Message",
            "type": "string"
          },
          "type": {
            "title": "Error Type",
            "type": "string"
          }
        },
        "required": [
          "loc",
          "msg",
          "type"
        ],
        "title": "ValidationError",
        "type": "object"
      },
      "title": "Detail",
      "type": "array"
    }
  },
  "title": "HTTPValidationError",
  "type": "object"
}
```



#### Example Request

```bash
curl -X POST 'http://localhost:8000/keys/generate' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "algorithm": "string"
}'
```

#### Example Response

```json
{
  "algorithm": "string",
  "created_at": 0.0,
  "expires_at": 0.0,
  "key_id": "string",
  "public_metadata": {}
}
```


### GET /keys/{key_id}

- Tags: keys
- Operation ID: `get_key_metadata_keys__key_id__get`
- Authentication: Required

Get Key Metadata


#### Request Schema


_No request body._


#### Response Schemas


Status `200`:

```json
{
  "additionalProperties": true,
  "title": "Response Get Key Metadata Keys  Key Id  Get",
  "type": "object"
}
```


Status `422`:

```json
{
  "properties": {
    "detail": {
      "items": {
        "properties": {
          "ctx": {
            "title": "Context",
            "type": "object"
          },
          "input": {
            "title": "Input"
          },
          "loc": {
            "items": {
              "type": "string"
            },
            "title": "Location",
            "type": "array"
          },
          "msg": {
            "title": "Message",
            "type": "string"
          },
          "type": {
            "title": "Error Type",
            "type": "string"
          }
        },
        "required": [
          "loc",
          "msg",
          "type"
        ],
        "title": "ValidationError",
        "type": "object"
      },
      "title": "Detail",
      "type": "array"
    }
  },
  "title": "HTTPValidationError",
  "type": "object"
}
```



#### Example Request

```bash
curl -X GET 'http://localhost:8000/keys/{key_id}' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <token>'
```

#### Example Response

```json
{}
```


### POST /keys/{key_id}/rotate

- Tags: keys
- Operation ID: `rotate_key_keys__key_id__rotate_post`
- Authentication: Required

Rotate Key


#### Request Schema


```json
{
  "properties": {
    "reason": {
      "minLength": 1,
      "title": "Reason",
      "type": "string"
    }
  },
  "required": [
    "reason"
  ],
  "title": "RotateKeyRequest",
  "type": "object"
}
```


#### Response Schemas


Status `200`:

```json
{
  "properties": {
    "algorithm": {
      "title": "Algorithm",
      "type": "string"
    },
    "new_key_id": {
      "title": "New Key Id",
      "type": "string"
    },
    "old_key_id": {
      "title": "Old Key Id",
      "type": "string"
    },
    "revoked_reason": {
      "title": "Revoked Reason",
      "type": "string"
    }
  },
  "required": [
    "old_key_id",
    "new_key_id",
    "algorithm",
    "revoked_reason"
  ],
  "title": "RotateKeyResponse",
  "type": "object"
}
```


Status `422`:

```json
{
  "properties": {
    "detail": {
      "items": {
        "properties": {
          "ctx": {
            "title": "Context",
            "type": "object"
          },
          "input": {
            "title": "Input"
          },
          "loc": {
            "items": {
              "type": "string"
            },
            "title": "Location",
            "type": "array"
          },
          "msg": {
            "title": "Message",
            "type": "string"
          },
          "type": {
            "title": "Error Type",
            "type": "string"
          }
        },
        "required": [
          "loc",
          "msg",
          "type"
        ],
        "title": "ValidationError",
        "type": "object"
      },
      "title": "Detail",
      "type": "array"
    }
  },
  "title": "HTTPValidationError",
  "type": "object"
}
```



#### Example Request

```bash
curl -X POST 'http://localhost:8000/keys/{key_id}/rotate' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "reason": "string"
}'
```

#### Example Response

```json
{
  "algorithm": "string",
  "new_key_id": "string",
  "old_key_id": "string",
  "revoked_reason": "string"
}
```


### GET /metrics

- Tags: system
- Operation ID: `metrics_endpoint_metrics_get`
- Authentication: Required

Metrics Endpoint


#### Request Schema


_No request body._


#### Response Schemas


Status `200`:

_No JSON schema._



#### Example Request

```bash
curl -X GET 'http://localhost:8000/metrics' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <token>'
```

#### Example Response

```json
{
  "message": "No schema available"
}
```


### GET /status

- Tags: system
- Operation ID: `status_status_get`
- Authentication: Required

Status


#### Request Schema


_No request body._


#### Response Schemas


Status `200`:

```json
{
  "properties": {
    "health": {
      "title": "Health",
      "type": "string"
    },
    "metrics": {
      "additionalProperties": true,
      "title": "Metrics",
      "type": "object"
    },
    "security_state": {
      "title": "Security State",
      "type": "string"
    },
    "timestamp": {
      "title": "Timestamp",
      "type": "number"
    }
  },
  "required": [
    "health",
    "timestamp",
    "security_state",
    "metrics"
  ],
  "title": "StatusResponse",
  "type": "object"
}
```



#### Example Request

```bash
curl -X GET 'http://localhost:8000/status' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <token>'
```

#### Example Response

```json
{
  "health": "string",
  "metrics": {},
  "security_state": "string",
  "timestamp": 0.0
}
```


