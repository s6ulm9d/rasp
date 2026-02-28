import { Sidebar } from '../components/Sidebar'
import { Header } from '../components/Header'

export default function DashboardPage() {
    return (
        <div className="flex h-screen overflow-hidden">
            <Sidebar />
            <div className="flex-1 flex flex-col h-full overflow-hidden">
                <Header />
                <main className="flex-1 overflow-y-auto p-6">
                    <div className="mb-6">
                        <h1 className="text-2xl font-bold mb-2">Security Overview</h1>
                        <p className="text-sm text-gray-400">Monitor unified real-time telemetry from your agents.</p>
                    </div>

                    <div className="grid grid-cols-4 gap-4 mb-6">
                        {[
                            { label: 'Total Events / 24h', value: '1,420', trend: '+12%' },
                            { label: 'Blocked Attacks', value: '482', trend: '+5%' },
                            { label: 'Avg Anomaly Score', value: '0.84', trend: '-0.02' },
                            { label: 'Active Agents', value: '8', trend: 'Stable' },
                        ].map((stat, i) => (
                            <div key={i} className="bg-surface border border-border rounded-lg p-5">
                                <p className="text-gray-400 text-sm mb-1">{stat.label}</p>
                                <div className="flex items-baseline gap-2">
                                    <h3 className="text-2xl font-bold">{stat.value}</h3>
                                    <span className={`text-xs ${stat.trend.startsWith('+') ? 'text-critical' : 'text-info'}`}>
                                        {stat.trend}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>

                    <div className="bg-surface border border-border rounded-lg p-6 min-h-[400px]">
                        <h2 className="text-lg font-semibold mb-4">Live Attack Stream</h2>
                        <div className="flex items-center justify-center h-64 text-gray-500 text-sm italic">
                            Awaiting websocket events...
                        </div>
                    </div>
                </main>
            </div>
        </div>
    )
}
