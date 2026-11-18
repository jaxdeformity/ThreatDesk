import { createBrowserRouter, Navigate } from 'react-router-dom'
import { Shell } from '@/shell/Shell'
import { TriageView } from '@/features/triage/TriageView'
import { VulnsView } from '@/features/vulns/VulnsView'
import { ThreatIntelView } from '@/features/threat-intel/ThreatIntelView'
import { SettingsView } from '@/features/settings/SettingsView'

export const routes = [
  {
    path: '/',
    element: <Shell />,
    children: [
      { index: true, element: <Navigate to="/vulns" replace /> },
      { path: 'vulns', element: <VulnsView /> },
      { path: 'triage', element: <TriageView /> },
      { path: 'intel', element: <ThreatIntelView /> },
      { path: 'settings', element: <SettingsView /> },
      { path: '*', element: <Navigate to="/vulns" replace /> },
    ],
  },
]

export const router = createBrowserRouter(routes)
