import Link from 'next/link'
import { LayoutDashboard, Shield, Server, Bell, FileText, Settings } from 'lucide-react'

export function Sidebar() {
    return (
        <div className="w-64 border-r border-border h-full bg-surface flex flex-col">
            <div className="p-6">
                <h1 className="text-xl font-bold flex items-center gap-2">
                    <Shield className="text-info" /> ShieldRASP
                </h1>
            </div>
            <nav className="flex-1 px-4 space-y-2">
                <Link href="/" className="flex items-center gap-3 px-3 py-2 rounded-md hover:bg-border transition-colors text-sm font-medium">
                    <LayoutDashboard size={18} /> Dashboard
                </Link>
                <Link href="/events" className="flex items-center gap-3 px-3 py-2 rounded-md hover:bg-border transition-colors text-sm font-medium">
                    <Shield size={18} /> Attack Events
                </Link>
                <Link href="/agents" className="flex items-center gap-3 px-3 py-2 rounded-md hover:bg-border transition-colors text-sm font-medium">
                    <Server size={18} /> Agents
                </Link>
                <Link href="/rules" className="flex items-center gap-3 px-3 py-2 rounded-md hover:bg-border transition-colors text-sm font-medium">
                    <Settings size={18} /> Detection Rules
                </Link>
                <Link href="/alerts" className="flex items-center gap-3 px-3 py-2 rounded-md hover:bg-border transition-colors text-sm font-medium">
                    <Bell size={18} /> Alerts
                </Link>
                <Link href="/reports" className="flex items-center gap-3 px-3 py-2 rounded-md hover:bg-border transition-colors text-sm font-medium">
                    <FileText size={18} /> Reports
                </Link>
            </nav>
        </div>
    )
}
