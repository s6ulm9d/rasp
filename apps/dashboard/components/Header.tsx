import { User, Bell, Search } from 'lucide-react'

export function Header() {
    return (
        <header className="h-16 border-b border-border bg-surface px-6 flex items-center justify-between">
            <div className="flex items-center bg-background rounded-md px-3 py-1.5 border border-border w-96">
                <Search size={16} className="text-gray-400 mr-2" />
                <input
                    type="text"
                    placeholder="Search events, IP addresses, or rules..."
                    className="bg-transparent border-none outline-none text-sm w-full"
                />
            </div>
            <div className="flex items-center gap-4">
                <button className="text-gray-400 hover:text-white transition-colors relative">
                    <Bell size={20} />
                    <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-critical rounded-full border border-surface"></span>
                </button>
                <div className="flex items-center gap-3 border-l border-border pl-4">
                    <div className="w-8 h-8 rounded-full bg-border flex items-center justify-center">
                        <User size={16} />
                    </div>
                    <div className="text-sm">
                        <p className="font-medium text-white leading-none mb-1">Admin User</p>
                        <p className="text-gray-400 text-xs leading-none">Security Ops</p>
                    </div>
                </div>
            </div>
        </header>
    )
}
