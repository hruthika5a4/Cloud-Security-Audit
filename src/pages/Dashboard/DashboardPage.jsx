import React, { useState, useEffect, useMemo } from 'react';

import Section from '../../components/Section/Section';
import Card from '../../components/Card/Card';
import ScheduleModal from '../../components/ScheduleModal/ScheduleModal';

const SERVICE_RANK = {
  'iam': 1,
  'compute': 2,
  'vm': 2,
  'ec2': 2,
  'storage': 3,
  's3': 3,
  'database': 4,
  'cloud sql': 4,
  'sql': 4,
  'rds': 4,
  'networking': 5,
  'firewall': 5,
  'kubernetes': 6,
  'gke': 6,
  'eks': 6,
  'load balancers': 7,
  'lb': 7,
  'serverless': 8,
  'cloud run': 8,
  'cloud functions': 8,
  'lambda': 8,
  'bigquery': 9,
  'kms': 10,
  'logging & monitoring': 11,
  'logging': 11,
  'monitoring': 11,
  'dataproc': 12,
  'cloud dns': 13,
  'dns': 13,
  'api keys': 14,
  'access transparency': 15,
  'essential contacts': 16,
  'other': 99
};

const getServiceName = (resource, id = '') => {
  if (id) {
    const parts = id.split('-');
    const prefix = (parts[1] || '').toUpperCase();
    if (prefix === 'IAM') return 'IAM';
    if (prefix === 'VM' || prefix === 'COMPUTE' || prefix === 'EC2') return 'Compute';
    if (prefix === 'STORAGE' || prefix === 'S3') return 'Storage';
    if (prefix === 'SQL' || prefix === 'RDS') return 'Database';
    if (prefix === 'NET' || prefix === 'FW' || prefix === 'FIREWALL') return 'Networking';
    if (prefix === 'GKE' || prefix === 'EKS') return 'Kubernetes';
    if (prefix === 'LB' || prefix === 'ELB') return 'Load Balancers';
    if (prefix === 'CLOUDRUN' || prefix === 'FUNCTION' || prefix === 'SERVERLESS' || prefix === 'LAMBDA') return 'Serverless';
    if (prefix === 'BQ' || prefix === 'BIGQUERY') return 'BigQuery';
    if (prefix === 'KMS') return 'KMS';
    if (prefix === 'LOG' || prefix === 'OBS' || prefix === 'MONITOR') {
      if (id.toUpperCase().includes('TRANSPARENCY')) return 'Access Transparency';
      return 'Logging & Monitoring';
    }
    if (prefix === 'DATAPROC') return 'Dataproc';
    if (prefix === 'DNS') return 'Cloud DNS';
    if (prefix === 'APIKEY') return 'API Keys';
    if (prefix === 'ESSENTIAL') return 'Essential Contacts';
  }

  const match = (resource || '').match(/^([^(]+)/);
  let sName = match ? match[1].trim() : 'Other';
  const lowerName = sName.toLowerCase();
  
  if (lowerName.includes('compute') || lowerName.includes('vm') || lowerName.includes('instance')) return 'Compute';
  if (lowerName.includes('iam') || lowerName.includes('service account')) return 'IAM';
  if (lowerName.includes('storage') || lowerName.includes('bucket')) return 'Storage';
  if (lowerName.includes('sql') || lowerName.includes('database') || lowerName.includes('rds')) return 'Database';
  if (lowerName.includes('network') || lowerName.includes('vpc') || lowerName.includes('firewall') || lowerName.includes('subnet')) return 'Networking';
  if (lowerName.includes('dns')) return 'Cloud DNS';
  if (lowerName.includes('kubernetes') || lowerName.includes('gke') || lowerName.includes('eks')) return 'Kubernetes';
  if (lowerName.includes('kms') || lowerName.includes('key')) return 'KMS';
  if (lowerName.includes('func') || lowerName.includes('lambda') || lowerName.includes('serverless') || lowerName.includes('cloudrun')) return 'Serverless';
  if (lowerName.includes('load balancer') || lowerName.includes('backend service') || lowerName.includes('lb')) return 'Load Balancers';
  if (lowerName.includes('bigquery') || lowerName.includes('bq') || lowerName.includes('dataset') || lowerName.includes('table')) return 'BigQuery';
  if (lowerName.includes('dataproc')) return 'Dataproc';
  if (lowerName.includes('api key')) return 'API Keys';
  if (lowerName.includes('transparency')) return 'Access Transparency';
  if (lowerName.includes('contact')) return 'Essential Contacts';
  if (lowerName.includes('logging') || lowerName.includes('monitoring') || lowerName.includes('audit log')) return 'Logging & Monitoring';
  
  return sName || 'Other';
};

const CHECKPOINT_DEFINITIONS = [
  // 1. IAM
  { prefix: 'IAM-USER-OWNER', name: 'IAM User with Owner / Primitive Roles', rank: 1 },
  { prefix: 'IAM-SA-ADMIN', name: 'Service Account with Admin Privileges', rank: 2 },
  { prefix: 'IAM-PROJECT-TOKEN', name: 'Service Account Token Creator & User Impersonation', rank: 3 },
  { prefix: 'IAM-KMS-SOD', name: 'Separation of Duties: KMS Cryptographic Roles', rank: 4 },
  { prefix: 'IAM-NET-SOD', name: 'Separation of Duties: Network Admin Roles', rank: 5 },
  { prefix: 'IAM-USER-KEY', name: 'User-Managed Service Account Keys', rank: 6 },
  { prefix: 'IAM-KEY-ROTATION', name: 'Service Account Key Rotation (90 Days)', rank: 7 },
  { prefix: 'IAM-USER-KEYS', name: 'IAM Access Keys & MFA Policy', rank: 1 },

  // 2. Compute Engine & EC2
  { prefix: 'VM-PUBLIC-IP', name: 'Public IP & Direct Internet Exposure', rank: 1 },
  { prefix: 'EC2-PUBLIC-IP', name: 'Public IP & Direct Internet Exposure', rank: 1 },
  { prefix: 'VM-PROJ-SSH', name: 'Project-Wide SSH Key Blocking', rank: 2 },
  { prefix: 'VM-INST-SSH', name: 'Instance-Level SSH Key Blocking', rank: 3 },
  { prefix: 'VM-PROJ-OSLOGIN', name: 'Centralized OS Login Policy (Project Level)', rank: 4 },
  { prefix: 'VM-INST-OSLOGIN', name: 'Centralized OS Login Policy (Instance Level)', rank: 5 },
  { prefix: 'VM-DEF-SA-FULL', name: 'Default Service Account Full API Access Scope', rank: 6 },
  { prefix: 'VM-DEF-SA', name: 'Default Compute Service Account Usage', rank: 7 },
  { prefix: 'VM-IP-FWD', name: 'IP Forwarding & Packet Routing', rank: 8 },
  { prefix: 'VM-SHIELDED', name: 'Shielded VM (vTPM & Integrity Monitoring)', rank: 9 },
  { prefix: 'VM-SERIAL', name: 'Serial Port Console Connection', rank: 10 },
  { prefix: 'VM-DISK-CMEK', name: 'Customer-Managed Encryption Keys (CMEK Disk)', rank: 11 },
  { prefix: 'VM-CONFIDENTIAL', name: 'Confidential Computing (Memory Encryption)', rank: 12 },
  { prefix: 'VM-DEL-PROT', name: 'VM Deletion Protection', rank: 13 },
  { prefix: 'VM-PREEMPT', name: 'Preemptible / Spot Instance Resilience', rank: 14 },

  // 3. Cloud Storage & S3
  { prefix: 'STORAGE-PUBLIC', name: 'Public Access & Anonymous Bucket Exposure', rank: 1 },
  { prefix: 'S3-PUBLIC-BLOCK', name: 'Public Access & S3 Block Policy', rank: 1 },
  { prefix: 'STORAGE-PAP', name: 'Public Access Prevention (PAP Enforcement)', rank: 2 },
  { prefix: 'STORAGE-UBLA', name: 'Uniform Bucket-Level Access (UBLA)', rank: 3 },
  { prefix: 'STORAGE-CMEK', name: 'Customer-Managed Encryption Keys (CMEK Storage)', rank: 4 },
  { prefix: 'STORAGE-VERS', name: 'Object Versioning & Anti-Ransomware', rank: 5 },
  { prefix: 'STORAGE-LOG', name: 'Storage Access & Audit Logging', rank: 6 },

  // 4. Databases (Cloud SQL & RDS)
  { prefix: 'SQL-PUBLIC', name: 'Public IP & Internet Exposure', rank: 1 },
  { prefix: 'SQL-OPEN', name: 'Open Ingress Network (0.0.0.0/0 Authorized)', rank: 2 },
  { prefix: 'RDS-PUBLIC-ACCESS', name: 'Publicly Accessible RDS Database', rank: 1 },
  { prefix: 'SQL-SSL', name: 'Enforce SSL/TLS In-Transit Encryption', rank: 3 },
  { prefix: 'SQL-BACKUP', name: 'Automated Daily Database Backups', rank: 4 },
  { prefix: 'SQL-PITR', name: 'Point-In-Time Recovery & Binary Logging', rank: 5 },
  { prefix: 'SQL-MY-FLAG-INFILE', name: 'MySQL Flag: local_infile (File Injection Prevention)', rank: 6 },
  { prefix: 'SQL-MY-FLAG-SHOWDB', name: 'MySQL Flag: skip_show_database (Schema Privacy)', rank: 7 },
  { prefix: 'SQL-PG-FLAG', name: 'PostgreSQL Security & Logging Flags', rank: 8 },
  { prefix: 'SQL-MS-FLAG-CHAIN', name: 'SQL Server Flag: Cross-DB Ownership Chaining', rank: 9 },
  { prefix: 'SQL-MS-FLAG-AUTH', name: 'SQL Server Flag: Contained Database Authentication', rank: 10 },

  // 5. Networking & Firewalls
  { prefix: 'FW-OPEN-SSH', name: 'Firewall Rule: Unrestricted Ingress Port 22 (SSH)', rank: 1 },
  { prefix: 'FW-OPEN-RDP', name: 'Firewall Rule: Unrestricted Ingress Port 3389 (RDP)', rank: 2 },
  { prefix: 'NET-PUBLIC-SSH', name: 'Open SSH Access (0.0.0.0/0 Port 22)', rank: 1 },
  { prefix: 'NET-PUBLIC-RDP', name: 'Open RDP Access (0.0.0.0/0 Port 3389)', rank: 2 },
  { prefix: 'FW-OPEN-DB', name: 'Firewall Rule: Unrestricted Database Ingress Ports', rank: 3 },
  { prefix: 'NET-DEFAULT', name: 'Default VPC Network Security Posture', rank: 4 },
  { prefix: 'NET-LEGACY', name: 'Legacy Network Usage', rank: 5 },
  { prefix: 'NET-FLOWLOGS', name: 'Subnet VPC Flow Logs Telemetry', rank: 6 },
  { prefix: 'NET-FLOW-LOGS', name: 'Subnet VPC Flow Logs Telemetry', rank: 6 },
  { prefix: 'NET-PGA', name: 'Private Google Access (PGA)', rank: 7 },
  { prefix: 'NET-LBLOG', name: 'Load Balancer Logging & Ingress Metrics', rank: 8 },

  // 6. Kubernetes (GKE & EKS)
  { prefix: 'GKE-PUBLIC-ENDPOINT-RESTRICTED', name: 'Kubernetes Master Public Authorized Networks', rank: 1 },
  { prefix: 'GKE-PUBLIC-ENDPOINT', name: 'Kubernetes Master Private Endpoint', rank: 2 },
  { prefix: 'EKS-PUBLIC-ENDPOINT', name: 'EKS Cluster Public API Endpoint', rank: 1 },
  { prefix: 'GKE-WORKLOAD-IDENTITY', name: 'Workload Identity Federation', rank: 3 },
  { prefix: 'GKE-LEGACY-ABAC', name: 'Legacy ABAC Authorization', rank: 4 },
  { prefix: 'GKE-SHIELDED-NODES', name: 'Shielded GKE Nodes & Integrity Monitoring', rank: 5 },
  { prefix: 'GKE-BINARY-AUTH', name: 'Binary Authorization & Container Signing', rank: 6 },

  // 7. Load Balancers
  { prefix: 'LB-NO-SSL-POLICY', name: 'Modern SSL / TLS Security Policy', rank: 1 },
  { prefix: 'LB-NO-CLOUD-ARMOR', name: 'Cloud Armor WAF & Anti-DDoS Protection', rank: 2 },
  { prefix: 'LB-NO-HTTPS-REDIRECT', name: 'Enforce HTTPS Redirection', rank: 3 },
  { prefix: 'ELB-NO-DEL-PROTECTION', name: 'Load Balancer Deletion Protection', rank: 4 },

  // 8. Serverless
  { prefix: 'CLOUDRUN-PUBLIC-ACCESS', name: 'Cloud Run Unauthenticated Public Invocation', rank: 1 },
  { prefix: 'LAMBDA-PUBLIC-POLICY', name: 'Lambda Public / Wildcard Execution Policy', rank: 1 },
  { prefix: 'CLOUDRUN-ALLOW-ALL-INGRESS', name: 'Cloud Run Ingress Traffic Filtering', rank: 2 },
  { prefix: 'FUNCTION-ALLOW-ALL-INGRESS', name: 'Cloud Function Ingress Traffic Filtering', rank: 3 },
  { prefix: 'FUNCTION-DEFAULT-SA', name: 'Cloud Function Default Service Account', rank: 4 },

  // 9. BigQuery
  { prefix: 'BQ-DATASET-PUBLIC', name: 'Public / Anonymous Dataset Sharing (allUsers)', rank: 1 },
  { prefix: 'BQ-DATASET-ALLAUTH', name: 'Dataset allAuthenticatedUsers Permissive Sharing', rank: 2 },
  { prefix: 'BQ-DATASET-CMEK', name: 'Customer-Managed Encryption Keys (CMEK Dataset)', rank: 3 },

  // 10. KMS
  { prefix: 'KMS-ROTATION', name: 'Cryptographic Key Automated 90-Day Rotation', rank: 1 },
  { prefix: 'KMS-PROTECTION', name: 'Hardware Security Module (HSM) Protection Level', rank: 2 },
  { prefix: 'KMS-DESTROY', name: 'Key Scheduled Destruction Window Policy', rank: 3 },

  // 11. Logging & Monitoring
  { prefix: 'LOG-AUDIT', name: 'Default Data Access Audit Logging (All APIs)', rank: 1 },
  { prefix: 'LOG-BUCKET-LOCK', name: 'Audit Log Bucket Object Retention Lock', rank: 2 },
  { prefix: 'LOG-SINK', name: 'Centralized Security Export Log Sink', rank: 3 },
  { prefix: 'LOG-METRIC', name: 'CIS Benchmark Metric Alert & Notification Policy', rank: 4 },
  { prefix: 'OBS-ASSET', name: 'Cloud Asset Inventory Telemetry', rank: 5 },
  { prefix: 'OBS-TRANSPARENCY', name: 'Access Transparency Logging', rank: 6 },

  // 12. Auxiliary
  { prefix: 'DATAPROC-NO-ENCRYPTION', name: 'In-Transit & Internal IP Cluster Encryption', rank: 1 },
  { prefix: 'DATAPROC-NO-SHIELDED', name: 'Shielded Cluster Compute Nodes', rank: 2 },
  { prefix: 'DNS-NO-DNSSEC', name: 'DNSSEC Domain Security Extensions', rank: 1 },
  { prefix: 'DNS-RSASHA1', name: 'Strong DNSSEC Cryptographic Algorithm', rank: 2 },
  { prefix: 'APIKEY-NO-RESTRICTIONS', name: 'API Key Application & API Scope Restrictions', rank: 1 },
  { prefix: 'APIKEY-NO-ROTATION', name: 'API Key 90-Day Rotation Policy', rank: 2 },
  { prefix: 'ESSENTIAL-CONTACTS', name: 'Essential Contacts & Incident Notifications', rank: 1 }
];

const getCheckpointInfo = (id = '') => {
  if (!id) return { name: 'General Security Check', rank: 99 };
  const upperId = id.toUpperCase();
  for (const def of CHECKPOINT_DEFINITIONS) {
    if (upperId.includes(def.prefix)) {
      return { name: def.name, rank: def.rank };
    }
  }
  const parts = id.split('-');
  const checkType = parts[2] ? parts[2].toUpperCase() : 'GENERAL';
  return { name: `Check: ${checkType.charAt(0).toUpperCase() + checkType.slice(1).toLowerCase()}`, rank: 99 };
};

const getCheckpointName = (id) => getCheckpointInfo(id).name;

const DashboardPage = () => {
  const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' ? 'http://localhost:8000' : 'https://cloud-security-audit.onrender.com';

  const [scanData, setScanData] = useState(null);
  const [reportStatus, setReportStatus] = useState(null); // null | 'downloading' | 'sending' | 'sent' | 'error'
  const [reportMenuOpen, setReportMenuOpen] = useState(false);
  const [exportModalOpen, setExportModalOpen] = useState(false);
  const [exportType, setExportType] = useState('email'); // 'email' | 'download'
  const [emailInput, setEmailInput] = useState('');
  const [scheduleModalOpen, setScheduleModalOpen] = useState(false);
  const [selectedEmailServices, setSelectedEmailServices] = useState(['ALL']);
  const [includePdf, setIncludePdf] = useState(true);
  const [includeExcel, setIncludeExcel] = useState(false);

  // Filtering and Pagination State
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [serviceFilter, setServiceFilter] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  const servicesPerPage = 2;

  useEffect(() => {
    // Check if we came from ScanHistory with a specific scan object
    const historicalScan = localStorage.getItem('last_viewed_scan');
    const latestScan = localStorage.getItem('latest_scan_result');
    
    if (historicalScan) {
      console.log('Dashboard loading historical scan data');
      const scan = JSON.parse(historicalScan);
      setScanData(scan);
      
      setTimeout(() => {
        window.dispatchEvent(new CustomEvent('scanCompleted', { detail: scan }));
      }, 50);
      
      localStorage.removeItem('last_viewed_scan');
    } else if (latestScan) {
      console.log('Dashboard loading latest background scan data');
      const scan = JSON.parse(latestScan);
      setScanData(scan);
      
      setTimeout(() => {
        window.dispatchEvent(new CustomEvent('scanCompleted', { detail: scan }));
      }, 50);
    }
  }, []);

  useEffect(() => {
    const handleScanComplete = (e) => {
      console.log('Dashboard received new scan data:', e.detail);
      setScanData(e.detail);
      // Reset filters on new scan
      setSearchTerm('');
      setSeverityFilter('All');
      setServiceFilter('all');
      setCurrentPage(1);
    };

    const handleServiceFilterChanged = (e) => {
      setServiceFilter(e.detail);
      setCurrentPage(1);
    };

    const handleScanStarted = () => {
      setScanData(null);
    };

    window.addEventListener('scanCompleted', handleScanComplete);
    window.addEventListener('scanStarted', handleScanStarted);
    return () => {
      window.removeEventListener('scanCompleted', handleScanComplete);
      window.removeEventListener('scanStarted', handleScanStarted);
    };
  }, []);
  // New: Compute Scan Coverage for Dashboard Overview
  const dashboardCoverage = useMemo(() => {
    if (!scanData) return { percent: 100, completed: 0, total: 0, skipped: [] };
    const total = scanData.totalChecks || 77; // Default to the new 77-checkpoint standard
    const skippedArr = scanData.skippedChecks ? JSON.parse(scanData.skippedChecks) : [];
    const completed = total - skippedArr.length;
    return {
      percent: Math.round((completed / total) * 100),
      completed,
      total,
      skipped: skippedArr
    };
  }, [scanData]);
  // New: Listen for provider selection changes for empty state icon
  const [activeProvider, setActiveProvider] = useState(localStorage.getItem('auditscope_selected_provider') || 'gcp');

  useEffect(() => {
    const handleStorageChange = () => {
      setActiveProvider(localStorage.getItem('auditscope_selected_provider') || 'gcp');
    };
    window.addEventListener('storage', handleStorageChange);
    // Also poll slightly if local storage isn't triggering (same tab issue)
    const interval = setInterval(handleStorageChange, 1000);
    return () => {
      window.removeEventListener('storage', handleStorageChange);
      clearInterval(interval);
    };
  }, []);

  // Compute filtered and paginated results grouped by service
  const processedData = useMemo(() => {
    if (!scanData || !scanData.vulnerabilities || !Array.isArray(scanData.vulnerabilities)) return { paginatedServices: [], totalPages: 0, totalItems: 0, filteredAllItems: [] };

    let filtered = [...scanData.vulnerabilities];

    // Apply Service Filter (from Navbar)
    if (serviceFilter !== 'all') {
      filtered = filtered.filter(v => {
        return getServiceName(v.resource, v.id) === serviceFilter;
      });
    }

    // Apply Severity Filter
    if (severityFilter !== 'All') {
      filtered = filtered.filter(v => v.severity === severityFilter);
    }

    // Apply Search Filter (searches resource name, ID, or issue description)
    if (searchTerm) {
      const lowerTerm = searchTerm.toLowerCase();
      filtered = filtered.filter(v =>
        (v.resource && v.resource.toLowerCase().includes(lowerTerm)) ||
        (v.id && v.id.toLowerCase().includes(lowerTerm)) ||
        (v.issue && v.issue.toLowerCase().includes(lowerTerm))
      );
    }

    // Group by Service
    const groups = {};
    filtered.forEach(v => {
      const sName = getServiceName(v.resource, v.id);
      if (!groups[sName]) groups[sName] = [];
      groups[sName].push(v);
    });

    const SEV_RANK = {
      'Critical': 1,
      'High': 2,
      'Medium': 3,
      'Low': 4
    };

    const groupedServices = Object.keys(groups)
      .sort((a, b) => {
        const rankA = SERVICE_RANK[a.toLowerCase()] || 99;
        const rankB = SERVICE_RANK[b.toLowerCase()] || 99;
        if (rankA !== rankB) return rankA - rankB;
        return a.localeCompare(b);
      })
      .map(sName => {
        // Further group items within each service by Checkpoint
        const checkpointGroups = {};
        const checkpointRanks = {};
        groups[sName].forEach(v => {
          const cpInfo = getCheckpointInfo(v.id);
          const cpName = cpInfo.name;
          if (!checkpointGroups[cpName]) {
            checkpointGroups[cpName] = [];
            checkpointRanks[cpName] = cpInfo.rank;
          }
          checkpointGroups[cpName].push(v);
        });

        // Sort checkpoints inside this service by their importance / rank
        const sortedCheckpoints = Object.keys(checkpointGroups)
          .sort((a, b) => {
            const rankA = checkpointRanks[a] !== undefined ? checkpointRanks[a] : 99;
            const rankB = checkpointRanks[b] !== undefined ? checkpointRanks[b] : 99;
            if (rankA !== rankB) return rankA - rankB;
            return a.localeCompare(b);
          })
          .map(cpName => ({
            name: cpName,
            items: checkpointGroups[cpName].sort((x, y) => (SEV_RANK[x.severity] || 9) - (SEV_RANK[y.severity] || 9))
          }));

        return {
          name: sName,
          totalItems: groups[sName].length,
          checkpoints: sortedCheckpoints
        };
      });

    // Calculate Pagination on Services
    const totalPages = Math.ceil(groupedServices.length / servicesPerPage);
    const startIndex = (currentPage - 1) * servicesPerPage;
    const paginatedServices = groupedServices.slice(startIndex, startIndex + servicesPerPage);

    return {
      totalItems: filtered.length,
      filteredAllItems: filtered,
      paginatedServices,
      totalPages
    };
  }, [scanData, searchTerm, severityFilter, serviceFilter, currentPage]);

  const allServices = useMemo(() => {
    if (!scanData || !scanData.vulnerabilities || !Array.isArray(scanData.vulnerabilities)) return [];
    const services = new Set();
    scanData.vulnerabilities.forEach(v => {
      services.add(getServiceName(v.resource, v.id));
    });
    return Array.from(services).sort((a, b) => {
      const rankA = SERVICE_RANK[a.toLowerCase()] || 99;
      const rankB = SERVICE_RANK[b.toLowerCase()] || 99;
      if (rankA !== rankB) return rankA - rankB;
      return a.localeCompare(b);
    });
  }, [scanData]);

  const handleServiceCheckboxChange = (service) => {
    if (service === 'ALL') {
       setSelectedEmailServices(['ALL']);
       return;
    }
    
    let newSelected = selectedEmailServices.filter(s => s !== 'ALL');
    
    if (selectedEmailServices.includes('ALL')) {
      newSelected = [service];
    } else {
      if (newSelected.includes(service)) {
         newSelected = newSelected.filter(s => s !== service);
      } else {
         newSelected.push(service);
      }
    }
    
    if (newSelected.length === 0 || newSelected.length === allServices.length) {
       newSelected = ['ALL'];
    }
    
    setSelectedEmailServices(newSelected);
  };

  // Handle page change ensuring boundaries
  const handlePageChange = (newPage) => {
    if (newPage >= 1 && newPage <= processedData.totalPages) {
      setCurrentPage(newPage);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Critical': return '#ef4444'; // Red
      case 'High': return '#f97316'; // Orange
      case 'Medium': return '#eab308'; // Yellow
      case 'Low': return '#3b82f6'; // Blue
      default: return 'var(--color-text)';
    }
  };

  const handleDownloadReport = async () => {
    if (!scanData) return;
    setReportMenuOpen(false);
    setExportModalOpen(false);
    setReportStatus('downloading');
    try {
      let payloadData = JSON.parse(JSON.stringify(scanData));
      if (!selectedEmailServices.includes('ALL')) {
        payloadData.vulnerabilities = payloadData.vulnerabilities.filter(v => 
          selectedEmailServices.includes(getServiceName(v.resource, v.id))
        );
        payloadData.scanned = new Set(payloadData.vulnerabilities.map(v => v.resource)).size;
      }

      const token = localStorage.getItem('auditscope_token');
      const res = await fetch(`${API_BASE}/api/reports/download`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ scanData: payloadData, selectedServices: selectedEmailServices })
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error);
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `AuditScope_Report_${new Date().toISOString().slice(0, 10)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      setReportStatus(null);
    } catch (err) {
      console.error('Download error:', err);
      setReportStatus('error');
      setTimeout(() => setReportStatus(null), 4000);
    }
  };

  const handleEmailReport = async () => {
    if (!scanData || !emailInput) return;
    setReportStatus('sending');
    try {
      let payloadData = JSON.parse(JSON.stringify(scanData));
      if (!selectedEmailServices.includes('ALL')) {
        payloadData.vulnerabilities = payloadData.vulnerabilities.filter(v => 
          selectedEmailServices.includes(getServiceName(v.resource, v.id))
        );
        payloadData.scanned = new Set(payloadData.vulnerabilities.map(v => v.resource)).size;
      }

      const token = localStorage.getItem('auditscope_token');
      const res = await fetch(`${API_BASE}/api/reports/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ scanData: payloadData, recipientEmail: emailInput, selectedServices: selectedEmailServices, sendPdf: includePdf, sendExcel: includeExcel })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);

      setReportStatus('sent');
      setTimeout(() => {
        setReportStatus(null);
        setExportModalOpen(false);
        setEmailInput('');
      }, 2000);
    } catch (err) {
      console.error('Email error:', err);
      setReportStatus('error');
      setTimeout(() => setReportStatus(null), 4000);
    }
  };

  const handleDownloadExcel = async () => {
    if (!scanData) return;
    setReportMenuOpen(false);
    setReportStatus('downloading');
    try {
      const token = localStorage.getItem('auditscope_token');
      // For Excel, we use the scan record ID if available, or pass the current data
      // If scanData.id is from DB, use it, otherwise use the scanId if it's history
      const scanId = scanData.id || scanData.dbScanId;
      
      const res = await fetch(`${API_BASE}/api/reports/export-excel`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ 
          scanId: scanId,
          scanData: !scanId ? scanData : null // Send raw data only if ID is missing
        })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || 'Failed to export Excel.');
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `AuditScope_Report_${scanData.provider.toUpperCase()}_${new Date().toISOString().slice(0, 10)}.xlsx`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      setReportStatus(null);
    } catch (err) {
      console.error('Excel export error:', err);
      setReportStatus('error');
      setTimeout(() => setReportStatus(null), 4000);
    }
  };

  return (
    <>
      <div style={{ paddingBottom: 'var(--spacing-4)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 'var(--spacing-4)' }}>
          <div>
            <h1 style={{ fontSize: 'var(--font-size-xl)', marginBottom: 'var(--spacing-1)', display: 'flex', alignItems: 'center', gap: '12px' }}>
              {scanData && (
                <span style={{ display: 'flex', alignItems: 'center' }}>
                  {scanData.provider === 'aws' ? (
                    <svg viewBox="0 0 256 154" width="32" height="32"><path fill="#FF9900" d="M128 32c-34 0-61 17-61 46 0 18 10 32 29 39-4 3-5 5-5 8 0 4 3 6 8 6 10 0 22-9 33-19 16 10 36 15 54 15 36 0 61-17 61-46 0-14-6-26-17-34-14-11-36-16-59-16l-43 1z"/><path fill="#FF9900" d="M128 0c-45 0-82 25-82 56 0 20 16 38 41 48-12 13-33 24-58 29-5 1-4 3 1 3 45 0 86-21 106-53 23 10 49 16 77 16 45 0 82-25 82-56S259 0 214 0c-26 0-48 7-66 18C132 8 111 0 86 0z"/></svg>
                  ) : scanData.provider === 'azure' ? (
                    <svg viewBox="0 0 24 24" width="28" height="28"><path fill="#0078D4" d="M11.4 5.3l-8.5 13.4H12l2.6-4.1H7.8l5.2-8.3L11.4 5.3z M21.1 18.7l-9.7-15.4L8.8 7.4l6.4 11.3H21.1z"/></svg>
                  ) : (
                    <svg viewBox="0 0 24 24" width="22" height="22"><path fill="#4285F4" d="M12 2L4.5 20.29l.71.71L12 18l6.79 3 .71-.71L12 2z"/></svg>
                  )}
                </span>
              )}
              {scanData ? `${scanData.provider.toUpperCase()} Infrastructure Overview` : 'Overview'}
              {scanData?.isHistory && (
                <span style={{ fontSize: '10px', padding: '2px 8px', backgroundColor: 'rgba(0,0,0,0.05)', borderRadius: '10px', color: 'var(--color-text-muted)', fontWeight: 400 }}>Historical</span>
              )}
            </h1>
            <p style={{ color: 'var(--color-text-muted)', fontSize: 'var(--font-size-sm)', margin: 0 }}>
              {scanData ? (scanData.isHistory ? 'Historical security audit results.' : 'Latest security audit results.') : 'Select a Cloud Provider and click "Scan" to begin.'}
            </p>
          </div>
          {scanData && (
            <div style={{ position: 'relative' }}>
              <button
                onClick={() => setReportMenuOpen(!reportMenuOpen)}
                disabled={reportStatus === 'downloading' || reportStatus === 'sending'}
                style={{
                  padding: '6px 14px',
                  fontSize: '12px',
                  fontWeight: 700,
                  border: 'none',
                  borderRadius: '6px',
                  cursor: (reportStatus === 'downloading' || reportStatus === 'sending') ? 'wait' : 'pointer',
                  background: reportStatus === 'sent' ? 'var(--color-success)' : reportStatus === 'error' ? 'var(--color-danger)' : 'var(--color-primary)',
                  color: '#000',
                  transition: 'all 0.2s',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.02em'
                }}
              >
                {reportStatus === 'downloading' ? '⏳ Downloading...' :
                  reportStatus === 'sending' ? '⏳ Sending Email...' :
                    reportStatus === 'sent' ? '✅ Success' :
                      reportStatus === 'error' ? '❌ Failed' :
                        <>📄 Report <span style={{ fontSize: '10px', marginLeft: '2px' }}>▼</span></>}
              </button>

              {reportMenuOpen && (
                <div style={{
                  position: 'absolute',
                  top: '100%',
                  right: 0,
                  marginTop: '8px',
                  backgroundColor: 'var(--color-bg-secondary)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 'var(--radius-md)',
                  minWidth: '180px',
                  boxShadow: '0 4px 12px rgba(0,0,0,0.6)',
                  zIndex: 100,
                  overflow: 'hidden'
                }}>
                  <button
                    onClick={() => { setReportMenuOpen(false); setExportType('download'); setExportModalOpen(true); }}
                    style={{ width: '100%', padding: '12px 16px', background: 'none', border: 'none', borderBottom: '1px solid #2d3148', color: 'var(--color-text)', textAlign: 'left', cursor: 'pointer', fontSize: 'var(--font-size-sm)', display: 'flex', gap: '8px', alignItems: 'center' }}
                    onMouseOver={(e) => e.target.style.backgroundColor = 'rgba(0,0,0,0.05)'}
                    onMouseOut={(e) => e.target.style.backgroundColor = 'transparent'}
                  >
                    <span>⬇️</span> Download PDF
                  </button>
                  <button
                    onClick={handleDownloadExcel}
                    style={{ width: '100%', padding: '12px 16px', background: 'none', border: 'none', borderBottom: '1px solid #2d3148', color: 'var(--color-text)', textAlign: 'left', cursor: 'pointer', fontSize: 'var(--font-size-sm)', display: 'flex', gap: '8px', alignItems: 'center' }}
                    onMouseOver={(e) => e.target.style.backgroundColor = 'rgba(0,0,0,0.05)'}
                    onMouseOut={(e) => e.target.style.backgroundColor = 'transparent'}
                  >
                    <span>📊</span> Download Excel
                  </button>
                  <button
                    onClick={() => { setReportMenuOpen(false); setExportType('email'); setExportModalOpen(true); }}
                    style={{ width: '100%', padding: '12px 16px', background: 'none', border: 'none', color: 'var(--color-text)', textAlign: 'left', cursor: 'pointer', fontSize: 'var(--font-size-sm)', display: 'flex', gap: '8px', alignItems: 'center' }}
                    onMouseOver={(e) => e.target.style.backgroundColor = 'rgba(0,0,0,0.05)'}
                    onMouseOut={(e) => e.target.style.backgroundColor = 'transparent'}
                  >
                    <span>📧</span> Send via Email
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        {scanData ? (
          <>
            {/* Metrics overview */}
            {/* Premium Stats Grid */}
            <div style={{ 
              display: 'grid', 
              gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', 
              gap: 'var(--spacing-6)',
              marginBottom: 'var(--spacing-8)'
            }}>
              <div style={{ 
                background: 'var(--color-bg-secondary)', 
                padding: 'var(--spacing-6)',
                borderRadius: '16px',
                border: '1px solid var(--color-border)',
                boxShadow: 'var(--shadow-md)',
                position: 'relative',
                overflow: 'hidden'
              }}>
                <h3 style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--color-text-muted)', marginBottom: '8px', fontWeight: 600 }}>Total Vulnerabilities</h3>
                <div style={{ fontSize: '36px', fontWeight: 800, color: '#ef4444', letterSpacing: '-0.02em' }}>{processedData.totalItems}</div>
                <div style={{ marginTop: '12px', fontSize: '11px', color: 'var(--color-text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  Critical Findings: <span style={{ color: '#ef4444', fontWeight: 600 }}>{(scanData?.vulnerabilities || []).filter(f => f.severity === 'Critical').length}</span>
                </div>
              </div>

              <div style={{ 
                background: 'var(--color-bg-secondary)', 
                padding: 'var(--spacing-6)',
                borderRadius: '16px',
                border: '1px solid var(--color-border)',
                boxShadow: 'var(--shadow-md)',
                position: 'relative',
                overflow: 'hidden'
              }}>
                <h3 style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--color-text-muted)', marginBottom: '8px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
                  Resources Audited
                  <div style={{ position: 'relative', display: 'inline-block', cursor: 'help' }} 
                       onMouseEnter={(e) => {
                         const tooltip = e.currentTarget.querySelector('div[data-tooltip="resources"]');
                         if (tooltip) tooltip.style.opacity = '1';
                         if (tooltip) tooltip.style.visibility = 'visible';
                         if (tooltip) tooltip.style.transform = 'translate(-50%, 8px)';
                       }}
                       onMouseLeave={(e) => {
                         const tooltip = e.currentTarget.querySelector('div[data-tooltip="resources"]');
                         if (tooltip) tooltip.style.opacity = '0';
                         if (tooltip) tooltip.style.visibility = 'hidden';
                         if (tooltip) tooltip.style.transform = 'translate(-50%, 0)';
                       }}>
                    <span style={{ 
                      display: 'inline-flex', 
                      alignItems: 'center', 
                      justifyContent: 'center', 
                      width: '16px', 
                      height: '16px', 
                      borderRadius: '50%', 
                      border: '1px solid var(--color-border)', 
                      backgroundColor: 'rgba(100, 116, 139, 0.1)',
                      color: 'var(--color-text-muted)', 
                      fontSize: '10px', 
                      fontWeight: '700' 
                    }}>?</span>
                    <div data-tooltip="resources" style={{
                      opacity: '0',
                      visibility: 'hidden',
                      transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)',
                      position: 'absolute',
                      top: '100%',
                      left: '50%',
                      transform: 'translate(-50%, 0)',
                      backgroundColor: 'var(--color-bg)',
                      color: 'var(--color-text)',
                      padding: '16px',
                      borderRadius: '12px',
                      fontSize: '12px',
                      letterSpacing: 'normal',
                      textTransform: 'none',
                      boxShadow: 'var(--shadow-lg)',
                      width: 'max-content',
                      maxWidth: '280px',
                      border: '1px solid var(--color-border)',
                      zIndex: 10,
                      pointerEvents: 'none'
                    }}>
                      <div style={{ fontWeight: 700, marginBottom: '6px', color: 'var(--color-primary)', fontSize: '13px' }}>What are Resources?</div>
                      <div style={{ marginBottom: '12px', lineHeight: '1.5', color: 'var(--color-text)' }}>
                        A resource is a unique cloud entity evaluated during the audit, such as a VM instance, Storage bucket, or IAM role.
                      </div>
                      <div style={{ fontWeight: 700, marginBottom: '6px', color: 'var(--color-primary)', fontSize: '13px' }}>How is it calculated?</div>
                      <div style={{ lineHeight: '1.5', color: 'var(--color-text)' }}>
                        It's the count of <strong>unique</strong> resources evaluated.<br/><br/>
                        <span style={{ opacity: 0.85 }}><strong>Example:</strong> If 3 separate vulnerabilities are detected in a single "Backend-VM", it adds up to 3 Total Vulnerabilities, but only <strong>1 Resource Audited</strong>.</span>
                      </div>
                      {/* Tooltip Arrow Layer 1 (Border) */}
                      <div style={{
                        position: 'absolute',
                        bottom: '100%',
                        left: '50%',
                        marginLeft: '-6px',
                        borderWidth: '0 6px 6px 6px',
                        borderStyle: 'solid',
                        borderColor: 'transparent transparent var(--color-border) transparent'
                      }}></div>
                      {/* Tooltip Arrow Layer 2 (Background) */}
                      <div style={{
                        position: 'absolute',
                        bottom: 'calc(100% - 1px)',
                        left: '50%',
                        marginLeft: '-5px',
                        borderWidth: '0 5px 5px 5px',
                        borderStyle: 'solid',
                        borderColor: 'transparent transparent var(--color-bg) transparent'
                      }}></div>
                    </div>
                  </div>
                </h3>
                <div style={{ fontSize: '36px', fontWeight: 800, color: 'var(--color-text)', letterSpacing: '-0.02em' }}>
                  {scanData?.scanned !== undefined ? scanData.scanned : new Set(processedData.filteredAllItems.map(v => v.resource)).size}
                </div>
                <div style={{ marginTop: '12px', fontSize: '11px', color: 'var(--color-text-muted)' }}>
                  Audit Quality: <span style={{ color: dashboardCoverage.percent > 80 ? 'var(--color-primary)' : '#eab308', fontWeight: 600 }}>{dashboardCoverage.percent}%</span>
                  <span style={{ marginLeft: '8px', opacity: 0.8 }}>({dashboardCoverage.completed.toLocaleString()}/{dashboardCoverage.total.toLocaleString()} Validations)</span>
                </div>
                {dashboardCoverage.skipped.length > 0 && (
                  <div style={{ marginTop: '8px', display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                    {dashboardCoverage.skipped.slice(0, 3).map((s, i) => (
                      <span key={i} title={s.reason} style={{ fontSize: '9px', padding: '2px 6px', background: 'rgba(234, 179, 8, 0.1)', color: '#eab308', borderRadius: '4px', border: '1px solid rgba(234, 179, 8, 0.2)' }}>
                        {s.service} Skipped
                      </span>
                    ))}
                    {dashboardCoverage.skipped.length > 3 && <span style={{ fontSize: '9px', color: 'var(--color-text-muted)' }}>+{dashboardCoverage.skipped.length - 3} more</span>}
                  </div>
                )}
              </div>
            </div>

            {/* Premium Sticky Filter Bar */}
            <div style={{ 
              position: 'sticky', 
              top: 'calc(-1 * var(--spacing-8))', 
              zIndex: 900, 
              margin: '0 calc(-1 * var(--spacing-8))',
              padding: 'var(--spacing-4) var(--spacing-8)',
              backgroundColor: 'var(--color-bg)',
              opacity: 0.95,
              backdropFilter: 'blur(12px)',
              WebkitBackdropFilter: 'blur(12px)',
              borderBottom: '1px solid rgba(0,0,0,0.05)',
              display: 'flex',
              gap: 'var(--spacing-4)',
              alignItems: 'center',
              boxShadow: '0 4px 20px -10px rgba(0,0,0,0.1)',
              marginBottom: 'var(--spacing-6)'
            }}>
              <div style={{ flex: 1.5, position: 'relative' }}>
                <input
                  type="text"
                  placeholder="Search vulnerabilities..."
                  value={searchTerm}
                  onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
                  style={{
                    width: '100%',
                    height: '42px',
                    backgroundColor: 'var(--color-bg-secondary)',
                    border: '1px solid rgba(0,0,0,0.1)',
                    borderRadius: '10px',
                    padding: '0 15px 0 40px',
                    color: 'var(--color-text)',
                    fontSize: '14px',
                    outline: 'none',
                    transition: 'all 0.2s',
                    boxShadow: '0 2px 4px rgba(0,0,0,0.02)'
                  }}
                  onFocus={(e) => e.target.style.borderColor = 'var(--color-primary)'}
                  onBlur={(e) => e.target.style.borderColor = 'rgba(0,0,0,0.1)'}
                />
                <span style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', fontSize: '16px', opacity: 0.5 }}>🔍</span>
              </div>

              <div style={{ flex: 1, position: 'relative' }}>
                <select
                  value={serviceFilter}
                  onChange={(e) => { setServiceFilter(e.target.value); setCurrentPage(1); }}
                  style={{
                    width: '100%',
                    height: '42px',
                    backgroundColor: 'var(--color-bg-secondary)',
                    border: '1px solid rgba(0,0,0,0.1)',
                    borderRadius: '10px',
                    padding: '0 12px 0 35px',
                    color: 'var(--color-text)',
                    fontSize: '14px',
                    cursor: 'pointer',
                    outline: 'none',
                    appearance: 'none',
                    boxShadow: '0 2px 4px rgba(0,0,0,0.02)'
                  }}
                >
                  <option value="all">All Services</option>
                  {allServices.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <span style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', fontSize: '16px', opacity: 0.6 }}>🛠️</span>
                <span style={{ position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)', opacity: 0.3, fontSize: '10px' }}>▼</span>
              </div>

              <div style={{ flex: 1, position: 'relative' }}>
                <select
                  value={severityFilter}
                  onChange={(e) => { setSeverityFilter(e.target.value); setCurrentPage(1); }}
                  style={{
                    width: '100%',
                    height: '42px',
                    backgroundColor: 'var(--color-bg-secondary)',
                    border: '1px solid rgba(0,0,0,0.1)',
                    borderRadius: '10px',
                    padding: '0 12px 0 35px',
                    color: 'var(--color-text)',
                    fontSize: '14px',
                    cursor: 'pointer',
                    outline: 'none',
                    appearance: 'none',
                    boxShadow: '0 2px 4px rgba(0,0,0,0.02)'
                  }}
                >
                  <option value="All">All Severities</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
                <span style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', fontSize: '16px', opacity: 0.6 }}>🛡️</span>
                <span style={{ position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)', opacity: 0.4, fontSize: '10px' }}>▼</span>
              </div>
            </div>

            {/* Data Table */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--spacing-2)' }}>
                <h2 style={{ fontSize: 'var(--font-size-base)', margin: 0 }}>Vulnerability Findings <span style={{ color: 'var(--color-text-muted)', fontWeight: 400 }}>({processedData.totalItems})</span></h2>

                {/* Pagination Controls */}
                {processedData.totalPages > 1 && (
                  <div style={{ display: 'flex', gap: '4px', alignItems: 'center', fontSize: 'var(--font-size-sm)' }}>
                    <button
                      onClick={() => handlePageChange(currentPage - 1)}
                      disabled={currentPage === 1}
                      style={{ padding: '2px 8px', background: 'var(--color-background-light)', border: '1px solid var(--color-border)', borderRadius: '4px', color: currentPage === 1 ? 'var(--color-text-muted)' : 'var(--color-text)', cursor: currentPage === 1 ? 'not-allowed' : 'pointer' }}
                    >
                      Prev
                    </button>
                    <span style={{ margin: '0 8px', color: 'var(--color-text-muted)' }}>
                      Page {currentPage} of {processedData.totalPages}
                    </span>
                    <button
                      onClick={() => handlePageChange(currentPage + 1)}
                      disabled={currentPage === processedData.totalPages}
                      style={{ padding: '2px 8px', background: 'var(--color-background-light)', border: '1px solid var(--color-border)', borderRadius: '4px', color: currentPage === processedData.totalPages ? 'var(--color-text-muted)' : 'var(--color-text)', cursor: currentPage === processedData.totalPages ? 'not-allowed' : 'pointer' }}
                    >
                      Next
                    </button>
                  </div>
                )}
              </div>

              {processedData.paginatedServices.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-6)' }}>
                  {processedData.paginatedServices.map((serviceGroup, gIdx) => (
                    <div key={gIdx}>
                      <h3 style={{ fontSize: 'var(--font-size-lg)', marginBottom: 'var(--spacing-3)', paddingBottom: 'var(--spacing-2)', borderBottom: '1px solid var(--color-border)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ backgroundColor: 'var(--color-primary)', color: '#fff', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', textTransform: 'uppercase' }}>Service</span>
                        {serviceGroup.name}
                        <span style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-text-muted)', fontWeight: 400, marginLeft: 'auto' }}>
                          {serviceGroup.totalItems} items
                        </span>
                      </h3>
                      <Card style={{ padding: 0, overflow: 'hidden', border: 'none', background: 'transparent' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-4)' }}>
                          {serviceGroup.checkpoints.map((checkpoint, cpIdx) => (
                            <div key={cpIdx} style={{ backgroundColor: 'var(--color-bg-secondary)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--color-border)', overflow: 'hidden' }}>
                              <div style={{ backgroundColor: 'rgba(59, 130, 246, 0.05)', padding: '10px 16px', borderBottom: '1px solid var(--color-border)', color: 'var(--color-primary)', fontWeight: 700, fontSize: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <span style={{ display: 'flex' }}>
                                  <svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5s1.12-2.5 2.5-2.5 2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"/></svg>
                                </span> {checkpoint.name}
                              </div>
                              <div style={{ overflowX: 'auto' }}>
                                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 'var(--font-size-xs)' }}>
                                  <thead>
                                    <tr style={{ backgroundColor: 'transparent', borderBottom: '1px solid var(--color-border)' }}>
                                      <th style={{ padding: 'var(--spacing-3)', fontWeight: 600, color: 'var(--color-text-muted)', width: '12%' }}>ID</th>
                                      <th style={{ padding: 'var(--spacing-3)', fontWeight: 600, color: 'var(--color-text-muted)', width: '10%' }}>Severity</th>
                                      <th style={{ padding: 'var(--spacing-3)', fontWeight: 600, color: 'var(--color-text-muted)', width: '20%' }}>Resource</th>
                                      <th style={{ padding: 'var(--spacing-3)', fontWeight: 600, color: 'var(--color-text-muted)', width: '28%' }}>Issue Description</th>
                                      <th style={{ padding: 'var(--spacing-3)', fontWeight: 600, color: 'var(--color-text-muted)', width: '30%' }}>Recommendation</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {checkpoint.items.map((vuln, idx) => (
                                      <tr key={idx} style={{ borderBottom: idx === checkpoint.items.length - 1 ? 'none' : '1px solid var(--color-border)', backgroundColor: idx % 2 === 0 ? 'transparent' : 'rgba(0,0,0,0.01)' }}>
                                        <td style={{ padding: 'var(--spacing-3)', fontFamily: 'monospace', color: 'var(--color-primary)', fontWeight: 500 }}>
                                          {vuln.id}
                                        </td>
                                        <td style={{ padding: 'var(--spacing-3)' }}>
                                          <span style={{
                                            display: 'inline-block',
                                            padding: '2px 6px',
                                            borderRadius: '3px',
                                            backgroundColor: `${getSeverityColor(vuln.severity)}20`,
                                            color: getSeverityColor(vuln.severity),
                                            fontWeight: 700,
                                            fontSize: '10px',
                                            textTransform: 'uppercase'
                                          }}>
                                            {vuln.severity}
                                          </span>
                                        </td>
                                        <td style={{ padding: 'var(--spacing-3)', color: 'var(--color-text)', fontWeight: 500 }}>
                                          {vuln.resource}
                                        </td>
                                        <td style={{ padding: 'var(--spacing-3)', color: 'var(--color-text-muted)', lineHeight: '1.4' }}>
                                          {vuln.issue}
                                        </td>
                                        <td style={{ padding: 'var(--spacing-3)', color: 'var(--color-primary)', opacity: 0.9, lineHeight: '1.4' }}>
                                          {vuln.remediation || '-'}
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            </div>
                          ))}
                        </div>
                      </Card>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ padding: 'var(--spacing-8)', textAlign: 'center', color: 'var(--color-text-muted)', backgroundColor: 'var(--color-background-light)', borderRadius: 'var(--radius-lg)', border: '1px dashed var(--color-border)' }}>
                  No vulnerabilities match the current filters.
                </div>
              )}
            </div>
          </>
        ) : (
          <Section style={{ padding: 0 }} darker={false}>
            <Card style={{ minHeight: '300px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 'var(--spacing-4)' }}>
              <div style={{ opacity: 0.35, marginBottom: '24px', transition: 'all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275)' }}>
                {activeProvider === 'aws' ? (
                  <svg viewBox="0 0 256 154" width="100" height="100"><path fill="var(--color-primary)" d="M128 0c-45 0-82 25-82 56 0 20 16 38 41 48-12 13-33 24-58 29-5 1-4 3 1 3 45 0 86-21 106-53 23 10 49 16 77 16 45 0 82-25 82-56S259 0 214 0c-26 0-48 7-66 18C132 8 111 0 86 0z"/><path fill="var(--color-primary)" opacity="0.6" d="M128 32c-34 0-61 17-61 46 0 18 10 32 29 39-4 3-5 5-5 8 0 4 3 6 8 6 10 0 22-9 33-19 16 10 36 15 54 15 36 0 61-17 61-46 0-14-6-26-17-34-14-11-36-16-59-16l-43 1z"/></svg>
                ) : activeProvider === 'azure' ? (
                  <svg viewBox="0 0 24 24" width="100" height="100"><path fill="var(--color-primary)" d="M11.4 5.3l-8.5 13.4H12l2.6-4.1H7.8l5.2-8.3L11.4 5.3z M21.1 18.7l-9.7-15.4L8.8 7.4l6.4 11.3H21.1z"/></svg>
                ) : (
                  <svg viewBox="0 0 24 24" width="100" height="100">
                    <path fill="#4285F4" d="M12 2L4.5 20.29l.71.71L12 18l6.79 3 .71-.71L12 2z" opacity="0.3"/>
                    <path fill="#4285F4" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8z"/>
                  </svg>
                )}
              </div>
              <h3 style={{ color: 'var(--color-text)' }}>No active scans</h3>
              <p style={{ color: 'var(--color-text-muted)', textAlign: 'center', maxWidth: '400px', fontSize: 'var(--font-size-sm)' }}>
                Select "GCP" from the Choose Provider dropdown in the navigation bar and hit the Scan button to run a comprehensive multi-service audit.
              </p>
            </Card>
          </Section>
        )}
      </div>

      {/* Export Report Modal */}
      {exportModalOpen && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.7)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ backgroundColor: 'var(--color-bg-secondary)', padding: 'var(--spacing-6)', borderRadius: 'var(--radius-lg)', width: '100%', maxWidth: '400px', border: '1px solid var(--color-border)', boxShadow: 'var(--shadow-lg)' }}>
            <h2 style={{ fontSize: 'var(--font-size-lg)', marginBottom: 'var(--spacing-2)' }}>
              {exportType === 'email' ? 'Email Report' : 'Download PDF Report'}
            </h2>
            <p style={{ color: 'var(--color-text-muted)', fontSize: 'var(--font-size-sm)', marginBottom: 'var(--spacing-3)' }}>
              {exportType === 'email' ? 'Select services and enter the recipient email address to receive the PDF report.' : 'Select services to include in your downloaded PDF report.'}
            </p>
            
            <div style={{ marginBottom: 'var(--spacing-4)' }}>
              <label style={{ display: 'block', fontSize: 'var(--font-size-sm)', color: 'var(--color-text)', marginBottom: 'var(--spacing-2)', fontWeight: 600 }}>Include Services:</label>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '150px', overflowY: 'auto', padding: '8px', backgroundColor: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--color-text)', cursor: 'pointer' }}>
                  <input 
                    type="checkbox" 
                    checked={selectedEmailServices.includes('ALL')}
                    onChange={() => handleServiceCheckboxChange('ALL')}
                    style={{ cursor: 'pointer' }}
                  />
                  ALL
                </label>
                {allServices.map(service => (
                  <label key={service} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--color-text)', cursor: 'pointer' }}>
                    <input 
                      type="checkbox" 
                      checked={selectedEmailServices.includes('ALL') || selectedEmailServices.includes(service)}
                      onChange={() => handleServiceCheckboxChange(service)}
                      style={{ cursor: 'pointer' }}
                    />
                    {service}
                  </label>
                ))}
              </div>
            </div>

            {exportType === 'email' && (
              <div style={{ marginBottom: 'var(--spacing-4)' }}>
                <label style={{ display: 'block', fontSize: 'var(--font-size-sm)', color: 'var(--color-text)', marginBottom: 'var(--spacing-2)', fontWeight: 600 }}>Formats to Send:</label>
                <div style={{ display: 'flex', gap: '20px' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--color-text)', cursor: 'pointer' }}>
                    <input 
                      type="checkbox" 
                      checked={includePdf}
                      onChange={(e) => setIncludePdf(e.target.checked)}
                      style={{ cursor: 'pointer' }}
                    />
                    PDF Report
                  </label>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--color-text)', cursor: 'pointer' }}>
                    <input 
                      type="checkbox" 
                      checked={includeExcel}
                      onChange={(e) => setIncludeExcel(e.target.checked)}
                      style={{ cursor: 'pointer' }}
                    />
                    Excel Report
                  </label>
                </div>
              </div>
            )}

            {exportType === 'email' && (
              <input
                type="email"
                value={emailInput}
                onChange={e => setEmailInput(e.target.value)}
                placeholder="recipient@example.com"
                style={{ width: '100%', padding: '10px 14px', backgroundColor: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', color: 'var(--color-text)', marginBottom: 'var(--spacing-4)' }}
                autoFocus
              />
            )}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--spacing-3)' }}>
              <button
                onClick={() => setExportModalOpen(false)}
                disabled={reportStatus === 'sending' || reportStatus === 'downloading'}
                style={{ padding: '8px 16px', backgroundColor: 'transparent', border: '1px solid var(--color-border)', color: 'var(--color-text)', borderRadius: 'var(--radius-md)', cursor: (reportStatus === 'sending' || reportStatus === 'downloading') ? 'not-allowed' : 'pointer' }}
              >
                Cancel
              </button>
              {exportType === 'email' ? (
                <button
                  onClick={handleEmailReport}
                  disabled={!emailInput || (!includePdf && !includeExcel) || reportStatus === 'sending'}
                  style={{ padding: '8px 16px', backgroundColor: 'var(--color-primary)', border: 'none', color: '#fff', borderRadius: 'var(--radius-md)', cursor: (!emailInput || (!includePdf && !includeExcel) || reportStatus === 'sending') ? 'not-allowed' : 'pointer', opacity: (!emailInput || (!includePdf && !includeExcel) || reportStatus === 'sending') ? 0.6 : 1, display: 'flex', gap: '8px', alignItems: 'center' }}
                >
                  {reportStatus === 'sending' ? '⏳ Sending...' : '📧 Send Email'}
                </button>
              ) : (
                <button
                  onClick={handleDownloadReport}
                  disabled={reportStatus === 'downloading'}
                  style={{ padding: '8px 16px', backgroundColor: 'var(--color-primary)', border: 'none', color: '#fff', borderRadius: 'var(--radius-md)', cursor: reportStatus === 'downloading' ? 'not-allowed' : 'pointer', opacity: reportStatus === 'downloading' ? 0.6 : 1, display: 'flex', gap: '8px', alignItems: 'center' }}
                >
                  {reportStatus === 'downloading' ? '⏳ Downloading...' : '⬇️ Download'}
                </button>
              )}
            </div>
            {reportStatus === 'error' && (
              <p style={{ color: '#ef4444', fontSize: 'var(--font-size-sm)', marginTop: 'var(--spacing-3)', textAlign: 'center' }}>Failed to send email. Check backend logs or SMTP config.</p>
            )}
            {reportStatus === 'sent' && (
              <p style={{ color: '#22c55e', fontSize: 'var(--font-size-sm)', marginTop: 'var(--spacing-3)', textAlign: 'center' }}>Email sent successfully!</p>
            )}
          </div>
        </div>
      )}

      <ScheduleModal 
        isOpen={scheduleModalOpen}
        onClose={() => setScheduleModalOpen(false)}
        projectId={scanData?.dbProjectId}
        projectName={scanData?.provider?.toUpperCase() || 'Cloud'}
      />
    </>
  );
};

export default DashboardPage;
