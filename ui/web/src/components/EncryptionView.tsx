import React, { useCallback, useMemo, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  FormControl,
  FormControlLabel,
  Grid,
  InputLabel,
  LinearProgress,
  MenuItem,
  Paper,
  Select,
  Snackbar,
  Stack,
  Switch,
  TextField,
  Typography,
} from "@mui/material";
import type { SelectChangeEvent } from "@mui/material/Select";
import axios from "axios";
import type { AxiosProgressEvent } from "axios";
import { useDropzone } from "react-dropzone";


type Algorithm = "AES-GCM" | "ChaCha20" | "Kyber" | "Hybrid";
type Compression = "none" | "zstd" | "brotli";
type KeySize = 128 | 256 | 512;

interface EncryptionViewProps {
  apiBaseUrl?: string;
  authToken?: string;
}

interface EncryptApiResponse {
  key_id?: string;
  algorithm: string;
  encrypted_file_b64?: string;
  encrypted_file_url?: string;
  metadata?: Record<string, unknown>;
}

interface EncryptionResult {
  keyId?: string;
  algorithm: string;
  timestamp: string;
  originalSizeBytes: number;
  encryptedSizeBytes: number;
  metadata: Record<string, unknown>;
  blob: Blob;
}

const CHUNK_SIZE = 4 * 1024 * 1024;

const formatSize = (bytes: number): string => {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const kb = bytes / 1024;
  if (kb < 1024) {
    return `${kb.toFixed(2)} KB`;
  }
  const mb = kb / 1024;
  if (mb < 1024) {
    return `${mb.toFixed(2)} MB`;
  }
  const gb = mb / 1024;
  return `${gb.toFixed(2)} GB`;
};

const base64ToBlob = (base64: string): Blob => {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new Blob([bytes], { type: "application/octet-stream" });
};

const toApiAlgorithm = (algo: Algorithm): string => {
  if (algo === "ChaCha20") {
    return "CHACHA20-POLY1305";
  }
  if (algo === "Kyber") {
    return "KYBER-AES-GCM";
  }
  if (algo === "Hybrid") {
    return "KYBER-HYBRID";
  }
  return "AES-256-GCM";
};

const EncryptionView = ({ apiBaseUrl = "http://localhost:8000", authToken }: EncryptionViewProps) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [algorithm, setAlgorithm] = useState<Algorithm>("AES-GCM");
  const [compression, setCompression] = useState<Compression>("none");
  const [keySize, setKeySize] = useState<KeySize>(256);
  const [includeMetadata, setIncludeMetadata] = useState(true);
  const [metadataText, setMetadataText] = useState('{"owner":"security-team"}');

  const [isEncrypting, setIsEncrypting] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<EncryptionResult | null>(null);

  const [notification, setNotification] = useState<{ open: boolean; severity: "success" | "error"; message: string }>({
    open: false,
    severity: "success",
    message: "",
  });

  const headers = useMemo(() => {
    const token = authToken ?? window.localStorage.getItem("keycrypt_token") ?? "";
    return token ? { Authorization: `Bearer ${token}` } : {};
  }, [authToken]);

  const onDrop = useCallback((accepted: File[]) => {
    if (accepted.length > 0) {
      setSelectedFile(accepted[0]);
      setResult(null);
      setProgress(0);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: false,
  });

  const showError = (message: string) => {
    setNotification({ open: true, severity: "error", message });
  };

  const showSuccess = (message: string) => {
    setNotification({ open: true, severity: "success", message });
  };

  const buildUserMetadata = (): Record<string, unknown> => {
    if (!includeMetadata) {
      return {};
    }

    try {
      const parsed = JSON.parse(metadataText || "{}");
      if (parsed && typeof parsed === "object") {
        return parsed as Record<string, unknown>;
      }
      return {};
    } catch {
      throw new Error("Metadata must be valid JSON object");
    }
  };

  const directEncrypt = async (file: File, userMetadata: Record<string, unknown>): Promise<EncryptApiResponse> => {
    const formData = new FormData();
    formData.append("file", file);

    const response = await axios.post<EncryptApiResponse>(
      `${apiBaseUrl}/encrypt`,
      formData,
      {
        headers,
        params: {
          algorithm: toApiAlgorithm(algorithm),
          compression,
          key_size: keySize,
          metadata: JSON.stringify(userMetadata),
        },
        onUploadProgress: (evt: AxiosProgressEvent) => {
          if (!evt.total) {
            return;
          }
          setProgress(Math.min(95, Math.round((evt.loaded / evt.total) * 95)));
        },
      },
    );

    return response.data;
  };

  const uploadChunks = async (file: File, userMetadata: Record<string, unknown>): Promise<EncryptApiResponse> => {
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    const uploadId = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

    for (let index = 0; index < totalChunks; index += 1) {
      const start = index * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, file.size);
      const chunk = file.slice(start, end);

      const formData = new FormData();
      formData.append("chunk", chunk, `${file.name}.part${index}`);

      await axios.post(
        `${apiBaseUrl}/encrypt/chunk`,
        formData,
        {
          headers,
          params: {
            upload_id: uploadId,
            chunk_index: index,
            total_chunks: totalChunks,
            filename: file.name,
            algorithm: toApiAlgorithm(algorithm),
            compression,
            key_size: keySize,
            metadata: JSON.stringify(userMetadata),
          },
        },
      );

      const completed = ((index + 1) / totalChunks) * 90;
      setProgress(Math.round(completed));
    }

    const finalize = await axios.post<EncryptApiResponse>(
      `${apiBaseUrl}/encrypt/finalize`,
      {
        upload_id: uploadId,
        filename: file.name,
        algorithm: toApiAlgorithm(algorithm),
        compression,
        key_size: keySize,
        metadata: userMetadata,
      },
      { headers },
    );

    return finalize.data;
  };

  const handleEncrypt = async () => {
    if (!selectedFile) {
      showError("Please select a file first.");
      return;
    }

    let userMetadata: Record<string, unknown> = {};
    try {
      userMetadata = buildUserMetadata();
    } catch (err) {
      showError(err instanceof Error ? err.message : "Invalid metadata");
      return;
    }

    setIsEncrypting(true);
    setProgress(0);
    setResult(null);

    try {
      let response: EncryptApiResponse;

      if (selectedFile.size > CHUNK_SIZE) {
        try {
          response = await uploadChunks(selectedFile, userMetadata);
        } catch (chunkErr) {
          response = await directEncrypt(selectedFile, userMetadata);
        }
      } else {
        response = await directEncrypt(selectedFile, userMetadata);
      }

      let encryptedBlob: Blob;
      if (response.encrypted_file_b64) {
        encryptedBlob = base64ToBlob(response.encrypted_file_b64);
      } else if (response.encrypted_file_url) {
        const fileRes = await axios.get(response.encrypted_file_url, {
          headers,
          responseType: "blob",
        });
        encryptedBlob = fileRes.data as Blob;
      } else {
        throw new Error("No encrypted payload found in API response");
      }

      const encryptionResult: EncryptionResult = {
        keyId: response.key_id,
        algorithm: response.algorithm,
        timestamp: new Date().toISOString(),
        originalSizeBytes: selectedFile.size,
        encryptedSizeBytes: encryptedBlob.size,
        metadata: response.metadata ?? userMetadata,
        blob: encryptedBlob,
      };

      setResult(encryptionResult);
      setProgress(100);
      showSuccess("Encryption completed successfully.");
    } catch (err) {
      let message = "Encryption failed";
      if (axios.isAxiosError(err)) {
        const axiosErr = err as {
          message?: string;
          response?: { data?: { detail?: string } };
        };
        const detail = axiosErr.response?.data?.detail;
        message = detail ?? axiosErr.message ?? message;
      } else if (err instanceof Error) {
        message = err.message;
      }
      showError(String(message));
    } finally {
      setIsEncrypting(false);
    }
  };

  const handleDownload = () => {
    if (!result || !selectedFile) {
      return;
    }

    const url = URL.createObjectURL(result.blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${selectedFile.name}.enc`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <Box sx={{ p: { xs: 2, sm: 3 }, maxWidth: 1200, mx: "auto" }}>
      <Typography variant="h4" fontWeight={800} sx={{ mb: 0.5 }}>
        File Encryption
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Upload files, configure encryption options, and securely download encrypted output.
      </Typography>

      <Grid container spacing={2.5}>
        <Grid item xs={12} md={7}>
          <Card>
            <CardContent>
              <Typography variant="h6" fontWeight={700} sx={{ mb: 1.5 }}>
                Upload File
              </Typography>

              <Paper
                {...getRootProps()}
                variant="outlined"
                sx={{
                  p: { xs: 3, sm: 4 },
                  borderStyle: "dashed",
                  borderWidth: 2,
                  borderColor: isDragActive ? "primary.main" : "divider",
                  backgroundColor: isDragActive ? "action.hover" : "background.paper",
                  cursor: "pointer",
                  transition: "all 0.2s ease",
                  textAlign: "center",
                }}
              >
                <input {...getInputProps()} />
                <Typography variant="body1" fontWeight={600}>
                  {isDragActive ? "Drop file here" : "Drag and drop a file here"}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 0.7 }}>
                  or click to browse files
                </Typography>
              </Paper>

              {selectedFile && (
                <Stack direction="row" spacing={1.2} alignItems="center" sx={{ mt: 2 }}>
                  <Chip label={selectedFile.name} color="primary" variant="outlined" />
                  <Typography variant="body2" color="text.secondary">
                    {formatSize(selectedFile.size)}
                  </Typography>
                </Stack>
              )}

              <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} sx={{ mt: 2.5 }}>
                <Button variant="contained" onClick={handleEncrypt} disabled={!selectedFile || isEncrypting}>
                  {isEncrypting ? "Encrypting..." : "Encrypt File"}
                </Button>
                <Button variant="outlined" onClick={handleDownload} disabled={!result}>
                  Download Encrypted File
                </Button>
              </Stack>

              {(isEncrypting || progress > 0) && (
                <Box sx={{ mt: 2.5 }}>
                  <LinearProgress variant="determinate" value={progress} sx={{ height: 8, borderRadius: 6 }} />
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 0.8, display: "block" }}>
                    {progress}% complete
                  </Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={5}>
          <Card sx={{ height: "100%" }}>
            <CardContent>
              <Typography variant="h6" fontWeight={700} sx={{ mb: 1.5 }}>
                Encryption Options
              </Typography>

              <Stack spacing={1.8}>
                <FormControl size="small" fullWidth>
                  <InputLabel id="algo-label">Algorithm</InputLabel>
                  <Select
                    labelId="algo-label"
                    label="Algorithm"
                    value={algorithm}
                    onChange={(e: SelectChangeEvent<Algorithm>) => setAlgorithm(e.target.value as Algorithm)}
                  >
                    <MenuItem value="AES-GCM">AES-GCM</MenuItem>
                    <MenuItem value="ChaCha20">ChaCha20</MenuItem>
                    <MenuItem value="Kyber">Kyber</MenuItem>
                    <MenuItem value="Hybrid">Hybrid</MenuItem>
                  </Select>
                </FormControl>

                <FormControl size="small" fullWidth>
                  <InputLabel id="compression-label">Compression</InputLabel>
                  <Select
                    labelId="compression-label"
                    label="Compression"
                    value={compression}
                    onChange={(e: SelectChangeEvent<Compression>) => setCompression(e.target.value as Compression)}
                  >
                    <MenuItem value="none">None</MenuItem>
                    <MenuItem value="zstd">Zstd</MenuItem>
                    <MenuItem value="brotli">Brotli</MenuItem>
                  </Select>
                </FormControl>

                <FormControl size="small" fullWidth>
                  <InputLabel id="keysize-label">Key Size</InputLabel>
                  <Select
                    labelId="keysize-label"
                    label="Key Size"
                    value={String(keySize)}
                    onChange={(e: SelectChangeEvent<string>) => setKeySize(Number(e.target.value) as KeySize)}
                  >
                    <MenuItem value="128">128-bit</MenuItem>
                    <MenuItem value="256">256-bit</MenuItem>
                    <MenuItem value="512">512-bit</MenuItem>
                  </Select>
                </FormControl>

                <FormControlLabel
                  control={<Switch checked={includeMetadata} onChange={(_event: React.ChangeEvent<HTMLInputElement>, checked: boolean) => setIncludeMetadata(checked)} />}
                  label="Attach custom metadata"
                />

                <TextField
                  label="Metadata JSON"
                  multiline
                  minRows={4}
                  size="small"
                  disabled={!includeMetadata}
                  value={metadataText}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setMetadataText(e.target.value)}
                />
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" fontWeight={700} sx={{ mb: 1.5 }}>
                Encryption Metadata
              </Typography>

              {result ? (
                <Stack spacing={1}>
                  <Typography variant="body2"><Box component="span" sx={{ fontWeight: 700 }}>Algorithm:</Box> {result.algorithm}</Typography>
                  <Typography variant="body2"><Box component="span" sx={{ fontWeight: 700 }}>Key ID:</Box> {result.keyId ?? "N/A"}</Typography>
                  <Typography variant="body2"><Box component="span" sx={{ fontWeight: 700 }}>Timestamp:</Box> {new Date(result.timestamp).toLocaleString()}</Typography>
                  <Typography variant="body2"><Box component="span" sx={{ fontWeight: 700 }}>Original Size:</Box> {formatSize(result.originalSizeBytes)}</Typography>
                  <Typography variant="body2"><Box component="span" sx={{ fontWeight: 700 }}>Encrypted Size:</Box> {formatSize(result.encryptedSizeBytes)}</Typography>
                  <Typography variant="body2"><Box component="span" sx={{ fontWeight: 700 }}>Metadata:</Box></Typography>
                  <Paper variant="outlined" sx={{ p: 1.2, backgroundColor: "grey.50" }}>
                    <Typography variant="caption" component="pre" sx={{ whiteSpace: "pre-wrap", m: 0 }}>
                      {JSON.stringify(result.metadata, null, 2)}
                    </Typography>
                  </Paper>
                </Stack>
              ) : (
                <Alert severity="info">No encryption metadata yet. Encrypt a file to see details.</Alert>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Snackbar
        open={notification.open}
        autoHideDuration={4500}
        onClose={() => setNotification((prev: { open: boolean; severity: "success" | "error"; message: string }) => ({ ...prev, open: false }))}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
      >
        <Alert
          onClose={() => setNotification((prev: { open: boolean; severity: "success" | "error"; message: string }) => ({ ...prev, open: false }))}
          severity={notification.severity}
          variant="filled"
          sx={{ width: "100%" }}
        >
          {notification.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default EncryptionView;
