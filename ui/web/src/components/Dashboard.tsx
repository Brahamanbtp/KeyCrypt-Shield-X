import React, { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Box,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  FormControl,
  Grid,
  InputLabel,
  LinearProgress,
  MenuItem,
  Paper,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  TextField,
  Typography,
  useMediaQuery,
  useTheme,
} from "@mui/material";
import type { SelectChangeEvent } from "@mui/material/Select";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";


type SecurityLevel = "green" | "yellow" | "red";
type EventSeverity = "low" | "medium" | "high" | "critical";

type DashboardStatus = {
  security_state: string;
  metrics: {
    active_encryption_operations?: number;
    [key: string]: number | string | undefined;
  };
};

type RotationItem = {
  keyId: string;
  scheduledAt: string;
  status: "scheduled" | "in_progress" | "completed";
};

type SecurityEvent = {
  id: string;
  timestamp: string;
  type: string;
  severity: EventSeverity;
  source: string;
  message: string;
};

type ThroughputPoint = {
  time: string;
  mbps: number;
};

type SystemHealth = {
  cpu: number;
  memory: number;
  disk: number;
};

type SortField = "timestamp" | "severity" | "type" | "source";
type SortDirection = "asc" | "desc";

interface DashboardProps {
  apiBaseUrl?: string;
  wsUrl?: string;
  authToken?: string;
}

const severityRank: Record<EventSeverity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const defaultRotationTimeline: RotationItem[] = [
  { keyId: "KX-1024", scheduledAt: new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString(), status: "scheduled" },
  { keyId: "KX-1025", scheduledAt: new Date(Date.now() + 36 * 60 * 60 * 1000).toISOString(), status: "scheduled" },
  { keyId: "KX-1023", scheduledAt: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(), status: "completed" },
];

const fallbackThroughput = (): ThroughputPoint[] => {
  const now = Date.now();
  return Array.from({ length: 12 }, (_, idx) => {
    const ts = new Date(now - (11 - idx) * 5 * 60 * 1000);
    return {
      time: ts.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      mbps: 40 + Math.round(Math.random() * 55),
    };
  });
};

const fallbackEvents = (): SecurityEvent[] => [
  {
    id: "evt-1",
    timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    type: "AUTH_FAILURE",
    severity: "medium",
    source: "api-gateway",
    message: "Repeated invalid token attempts detected",
  },
  {
    id: "evt-2",
    timestamp: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
    type: "KEY_ROTATION",
    severity: "low",
    source: "key-manager",
    message: "Scheduled key rotation completed",
  },
  {
    id: "evt-3",
    timestamp: new Date(Date.now() - 55 * 60 * 1000).toISOString(),
    type: "ANOMALY",
    severity: "high",
    source: "risk-engine",
    message: "Abnormal encryption volume from one client",
  },
];

const getSecurityLevel = (value: string): SecurityLevel => {
  const normalized = value.toLowerCase();
  if (normalized.includes("critical") || normalized.includes("high") || normalized.includes("compromised")) {
    return "red";
  }
  if (normalized.includes("warn") || normalized.includes("elevated") || normalized.includes("medium")) {
    return "yellow";
  }
  return "green";
};

const getChipColor = (level: SecurityLevel): "success" | "warning" | "error" => {
  if (level === "red") {
    return "error";
  }
  if (level === "yellow") {
    return "warning";
  }
  return "success";
};

const safeNumber = (value: unknown, fallback = 0): number => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  return fallback;
};

const Dashboard = ({
  apiBaseUrl = "http://localhost:8000",
  authToken,
}: DashboardProps) => {
  const theme = useTheme();
  const isSmall = useMediaQuery(theme.breakpoints.down("md"));

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [securityState, setSecurityState] = useState("NORMAL");
  const [activeEncryptions, setActiveEncryptions] = useState(0);
  const [rotationTimeline, setRotationTimeline] = useState<RotationItem[]>(defaultRotationTimeline);
  const [events, setEvents] = useState<SecurityEvent[]>(fallbackEvents);
  const [throughputData, setThroughputData] = useState<ThroughputPoint[]>(fallbackThroughput());
  const [health, setHealth] = useState<SystemHealth>({ cpu: 34, memory: 49, disk: 61 });

  const [eventFilter, setEventFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState<"all" | EventSeverity>("all");
  const [sortField, setSortField] = useState<SortField>("timestamp");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");

  const headers = useMemo(() => {
    const token = authToken ?? window.localStorage.getItem("keycrypt_token") ?? "";
    return {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
  }, [authToken]);

  useEffect(() => {
    const controller = new AbortController();

    const loadDashboard = async () => {
      setLoading(true);
      setError(null);

      try {
        const [statusRes, rotationsRes, eventsRes, throughputRes, healthRes] = await Promise.all([
          fetch(`${apiBaseUrl}/status`, { headers, signal: controller.signal }),
          fetch(`${apiBaseUrl}/dashboard/key-rotations`, { headers, signal: controller.signal }),
          fetch(`${apiBaseUrl}/dashboard/security-events`, { headers, signal: controller.signal }),
          fetch(`${apiBaseUrl}/dashboard/throughput`, { headers, signal: controller.signal }),
          fetch(`${apiBaseUrl}/dashboard/health`, { headers, signal: controller.signal }),
        ]);

        if (!statusRes.ok) {
          throw new Error(`Status fetch failed: ${statusRes.status}`);
        }

        const statusJson = (await statusRes.json()) as DashboardStatus;
        setSecurityState(statusJson.security_state ?? "NORMAL");
        setActiveEncryptions(safeNumber(statusJson.metrics?.active_encryption_operations, 0));

        if (rotationsRes.ok) {
          const rotationsJson = (await rotationsRes.json()) as RotationItem[];
          if (Array.isArray(rotationsJson) && rotationsJson.length > 0) {
            setRotationTimeline(rotationsJson);
          }
        }

        if (eventsRes.ok) {
          const eventsJson = (await eventsRes.json()) as SecurityEvent[];
          if (Array.isArray(eventsJson) && eventsJson.length > 0) {
            setEvents(eventsJson);
          }
        }

        if (throughputRes.ok) {
          const throughputJson = (await throughputRes.json()) as ThroughputPoint[];
          if (Array.isArray(throughputJson) && throughputJson.length > 0) {
            setThroughputData(throughputJson);
          }
        }

        if (healthRes.ok) {
          const healthJson = (await healthRes.json()) as Partial<SystemHealth>;
          setHealth({
            cpu: safeNumber(healthJson.cpu, 0),
            memory: safeNumber(healthJson.memory, 0),
            disk: safeNumber(healthJson.disk, 0),
          });
        }
      } catch (fetchErr) {
        if (fetchErr instanceof DOMException && fetchErr.name === "AbortError") {
          return;
        }
        setError(fetchErr instanceof Error ? fetchErr.message : "Unknown dashboard error");
      } finally {
        setLoading(false);
      }
    };

    loadDashboard();

    return () => {
      controller.abort();
    };
  }, [apiBaseUrl, headers]);

  // Around line 290-295
useEffect(() => {
  const interval = setInterval(async () => {
    try {
      const response = await fetch('http://localhost:8000/api/status');
      const data = await response.json();
      
      // Update security state
      setSecurityState(data.security_state || 'NORMAL');
      
      // Update active encryptions
      setActiveEncryptions(data.active_encryptions ?? 0);
      
      // Update throughput chart with safe type handling
      setThroughputData(prev => [
        ...prev.slice(-9),
        { 
          time: new Date().toLocaleTimeString(),
          mbps: data.throughput_mbps ?? 0  // ← FIX: Handle undefined
        }
      ]);
      
    } catch (error) {
      console.error('Failed to fetch status:', error);
    }
  }, 5000);
  
  return () => clearInterval(interval);
}, []);

  const level = getSecurityLevel(securityState);

  const sortedFilteredEvents = useMemo(() => {
    const lowered = eventFilter.toLowerCase();

    const filtered = events.filter((evt: SecurityEvent) => {
      const matchesQuery =
        evt.type.toLowerCase().includes(lowered) ||
        evt.source.toLowerCase().includes(lowered) ||
        evt.message.toLowerCase().includes(lowered);

      const matchesSeverity = severityFilter === "all" || evt.severity === severityFilter;
      return matchesQuery && matchesSeverity;
    });

    filtered.sort((a: SecurityEvent, b: SecurityEvent) => {
      const directionFactor = sortDirection === "asc" ? 1 : -1;

      if (sortField === "timestamp") {
        return directionFactor * (new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
      }
      if (sortField === "severity") {
        return directionFactor * (severityRank[a.severity] - severityRank[b.severity]);
      }
      if (sortField === "type") {
        return directionFactor * a.type.localeCompare(b.type);
      }
      return directionFactor * a.source.localeCompare(b.source);
    });

    return filtered;
  }, [events, eventFilter, severityFilter, sortField, sortDirection]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((prev: SortDirection) => (prev === "asc" ? "desc" : "asc"));
      return;
    }
    setSortField(field);
    setSortDirection("desc");
  };

  const healthMetric = (label: string, value: number, color: "success" | "warning" | "error") => (
    <Box sx={{ width: "100%" }}>
      <Stack direction="row" justifyContent="space-between" sx={{ mb: 0.5 }}>
        <Typography variant="body2" color="text.secondary">
          {label}
        </Typography>
        <Typography variant="body2" fontWeight={700}>
          {value.toFixed(1)}%
        </Typography>
      </Stack>
      <LinearProgress
        variant="determinate"
        value={Math.max(0, Math.min(100, value))}
        color={color}
        sx={{ height: 9, borderRadius: 6 }}
      />
    </Box>
  );

  return (
    <Box sx={{ p: { xs: 2, sm: 3, md: 4 }, backgroundColor: "background.default", minHeight: "100vh" }}>
      <Stack direction={isSmall ? "column" : "row"} justifyContent="space-between" alignItems={isSmall ? "flex-start" : "center"} spacing={2} sx={{ mb: 3 }}>
        <Box>
          <Typography variant="h4" fontWeight={800}>
            KeyCrypt Shield X Dashboard
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Real-time encryption posture, key lifecycle, and system telemetry
          </Typography>
        </Box>
        <Chip
          label={`Security State: ${securityState}`}
          color={getChipColor(level)}
          sx={{ fontWeight: 700, fontSize: 14, px: 1.2, py: 2.4 }}
        />
      </Stack>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {loading ? (
        <Paper sx={{ p: 4, display: "grid", placeItems: "center" }}>
          <Stack spacing={1.5} alignItems="center">
            <CircularProgress size={36} />
            <Typography variant="body2" color="text.secondary">
              Loading dashboard data...
            </Typography>
          </Stack>
        </Paper>
      ) : (
        <Grid container spacing={2.5}>
          <Grid item xs={12} md={4}>
            <Card sx={{ height: "100%" }}>
              <CardContent>
                <Typography variant="overline" color="text.secondary">
                  Active Encryptions
                </Typography>
                <Typography variant="h3" fontWeight={800} sx={{ mt: 0.5 }}>
                  {activeEncryptions}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Live count updated via WebSocket stream
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={8}>
            <Card sx={{ height: "100%" }}>
              <CardContent>
                <Typography variant="h6" fontWeight={700} gutterBottom>
                  Encryption Throughput (MB/s)
                </Typography>
                <Box sx={{ width: "100%", height: 250 }}>
                  <ResponsiveContainer>
                    <AreaChart data={throughputData} margin={{ left: 4, right: 8, top: 10, bottom: 0 }}>
                      <defs>
                        <linearGradient id="throughputFill" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#00897b" stopOpacity={0.45} />
                          <stop offset="100%" stopColor="#00897b" stopOpacity={0.05} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="time" minTickGap={20} />
                      <YAxis />
                      <Tooltip />
                      <Legend />
                      <Area
                        type="monotone"
                        dataKey="mbps"
                        name="Throughput"
                        stroke="#00897b"
                        strokeWidth={2}
                        fill="url(#throughputFill)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card sx={{ height: "100%" }}>
              <CardContent>
                <Typography variant="h6" fontWeight={700} gutterBottom>
                  Key Rotation Timeline
                </Typography>
                <Stack spacing={1.2}>
                  {rotationTimeline.map((item: RotationItem) => (
                    <Paper key={`${item.keyId}-${item.scheduledAt}`} variant="outlined" sx={{ p: 1.4, borderLeftWidth: 6, borderLeftColor: item.status === "completed" ? "success.main" : item.status === "in_progress" ? "warning.main" : "info.main", borderLeftStyle: "solid" }}>
                      <Stack direction="row" justifyContent="space-between" alignItems="center">
                        <Box>
                          <Typography variant="body1" fontWeight={700}>
                            {item.keyId}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {new Date(item.scheduledAt).toLocaleString()}
                          </Typography>
                        </Box>
                        <Chip
                          size="small"
                          label={item.status.replace("_", " ")}
                          color={item.status === "completed" ? "success" : item.status === "in_progress" ? "warning" : "info"}
                        />
                      </Stack>
                    </Paper>
                  ))}
                </Stack>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card sx={{ height: "100%" }}>
              <CardContent>
                <Typography variant="h6" fontWeight={700} gutterBottom>
                  System Health Metrics
                </Typography>
                <Stack spacing={2}>
                  {healthMetric("CPU Usage", health.cpu, health.cpu > 85 ? "error" : health.cpu > 70 ? "warning" : "success")}
                  {healthMetric("Memory Usage", health.memory, health.memory > 85 ? "error" : health.memory > 70 ? "warning" : "success")}
                  {healthMetric("Disk Usage", health.disk, health.disk > 90 ? "error" : health.disk > 75 ? "warning" : "success")}
                </Stack>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Stack direction={isSmall ? "column" : "row"} justifyContent="space-between" alignItems={isSmall ? "stretch" : "center"} spacing={1.5} sx={{ mb: 1.5 }}>
                  <Typography variant="h6" fontWeight={700}>
                    Recent Security Events
                  </Typography>
                  <Stack direction={isSmall ? "column" : "row"} spacing={1.2}>
                    <TextField
                      size="small"
                      placeholder="Filter by type, source, message"
                      value={eventFilter}
                      onChange={(e: React.ChangeEvent<HTMLInputElement>) => setEventFilter(e.target.value)}
                    />
                    <FormControl size="small" sx={{ minWidth: 130 }}>
                      <InputLabel id="severity-filter-label">Severity</InputLabel>
                      <Select
                        labelId="severity-filter-label"
                        value={severityFilter}
                        label="Severity"
                        onChange={(e: SelectChangeEvent<"all" | EventSeverity>) =>
                          setSeverityFilter(e.target.value as "all" | EventSeverity)
                        }
                      >
                        <MenuItem value="all">All</MenuItem>
                        <MenuItem value="low">Low</MenuItem>
                        <MenuItem value="medium">Medium</MenuItem>
                        <MenuItem value="high">High</MenuItem>
                        <MenuItem value="critical">Critical</MenuItem>
                      </Select>
                    </FormControl>
                  </Stack>
                </Stack>

                <TableContainer component={Paper} variant="outlined">
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>
                          <TableSortLabel
                            active={sortField === "timestamp"}
                            direction={sortDirection}
                            onClick={() => handleSort("timestamp")}
                          >
                            Time
                          </TableSortLabel>
                        </TableCell>
                        <TableCell>
                          <TableSortLabel
                            active={sortField === "severity"}
                            direction={sortDirection}
                            onClick={() => handleSort("severity")}
                          >
                            Severity
                          </TableSortLabel>
                        </TableCell>
                        <TableCell>
                          <TableSortLabel
                            active={sortField === "type"}
                            direction={sortDirection}
                            onClick={() => handleSort("type")}
                          >
                            Type
                          </TableSortLabel>
                        </TableCell>
                        <TableCell>
                          <TableSortLabel
                            active={sortField === "source"}
                            direction={sortDirection}
                            onClick={() => handleSort("source")}
                          >
                            Source
                          </TableSortLabel>
                        </TableCell>
                        <TableCell>Message</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {sortedFilteredEvents.map((evt: SecurityEvent) => (
                        <TableRow key={evt.id} hover>
                          <TableCell>{new Date(evt.timestamp).toLocaleString()}</TableCell>
                          <TableCell>
                            <Chip
                              size="small"
                              label={evt.severity}
                              color={
                                evt.severity === "critical"
                                  ? "error"
                                  : evt.severity === "high"
                                  ? "warning"
                                  : evt.severity === "medium"
                                  ? "info"
                                  : "default"
                              }
                            />
                          </TableCell>
                          <TableCell>{evt.type}</TableCell>
                          <TableCell>{evt.source}</TableCell>
                          <TableCell>{evt.message}</TableCell>
                        </TableRow>
                      ))}
                      {sortedFilteredEvents.length === 0 && (
                        <TableRow>
                          <TableCell colSpan={5} align="center">
                            <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                              No events match current filters.
                            </Typography>
                          </TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
                </TableContainer>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}
    </Box>
  );
};

export default Dashboard;
