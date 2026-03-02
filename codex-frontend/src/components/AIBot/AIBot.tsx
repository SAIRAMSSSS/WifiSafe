import { useState, useEffect, useRef } from 'react';
import { X, Send, Sparkles, Shield, AlertTriangle, Zap, RefreshCw } from 'lucide-react';
import { aiAPI, securityAPI, alertAPI, threatAPI } from '@/lib/api';
import './AIBot.css';

interface Message {
    id: string;
    content: string;
    sender: 'bot' | 'user';
    timestamp: Date;
    suggestions?: string[];
}

interface SecurityData {
    score: number;
    alerts: number;
    criticalVulns: number;
    threats: number;
}

type EmotionState = 'happy' | 'neutral' | 'alert' | 'critical';

const AIBot = () => {
    const [isOpen, setIsOpen] = useState(false);
    const [isAnimatingIn, setIsAnimatingIn] = useState(true);
    const [isWaving, setIsWaving] = useState(false);
    const [isThinking, setIsThinking] = useState(false);
    const [emotion, setEmotion] = useState<EmotionState>('neutral');
    const [securityData, setSecurityData] = useState<SecurityData>({
        score: 0,
        alerts: 0,
        criticalVulns: 0,
        threats: 0
    });
    const [hasNewAlerts, setHasNewAlerts] = useState(false);
    const [messages, setMessages] = useState<Message[]>([]);
    const [inputValue, setInputValue] = useState('');
    const [chatAnimating, setChatAnimating] = useState(false);
    const messagesEndRef = useRef<HTMLDivElement>(null);

    // Initialize with welcome message based on security status
    useEffect(() => {
        const initBot = async () => {
            await fetchSecurityData();
        };
        initBot();
    }, []);

    // Pop-in animation on mount
    useEffect(() => {
        const timer = setTimeout(() => {
            setIsAnimatingIn(false);
            setIsWaving(true);
            setTimeout(() => setIsWaving(false), 1500);
        }, 600);
        return () => clearTimeout(timer);
    }, []);

    // Fetch security data and set emotion
    const fetchSecurityData = async () => {
        try {
            // Fetch multiple data sources in parallel
            const [scoreRes, alertsRes, threatsRes] = await Promise.allSettled([
                securityAPI.getScore(),
                alertAPI.getAll(),
                threatAPI.getStats()
            ]);

            const score = scoreRes.status === 'fulfilled' ? (scoreRes.value.data?.score ?? 50) : 50;
            const alerts = alertsRes.status === 'fulfilled' ? (scoreRes.value.data?.length ?? 0) : 0;
            const criticalVulns = threatsRes.status === 'fulfilled' ? (threatsRes.value.data?.critical ?? 0) : 0;

            setSecurityData({
                score,
                alerts,
                criticalVulns,
                threats: alerts
            });

            // Set emotion based on security score
            if (score < 30) {
                setEmotion('happy');
            } else if (score < 60) {
                setEmotion('neutral');
            } else if (score < 80) {
                setEmotion('alert');
            } else {
                setEmotion('critical');
            }

            // Set welcome message based on status
            const welcomeMsg = getWelcomeMessage(score, criticalVulns);
            setMessages([{
                id: '1',
                content: welcomeMsg,
                sender: 'bot',
                timestamp: new Date(),
                suggestions: ['Security Status', 'Run Scan', 'View Threats']
            }]);

            if (criticalVulns > 0 || score >= 70) {
                setHasNewAlerts(true);
            }

        } catch (error) {
            console.log('Could not fetch security data, using defaults');
            setMessages([{
                id: '1',
                content: "Hello! I'm CodeX AI, your security assistant. I can help you analyze threats, run scans, and provide security recommendations. How can I help?",
                sender: 'bot',
                timestamp: new Date(),
                suggestions: ['Security Status', 'Run Scan', 'Help']
            }]);
        }
    };

    const getWelcomeMessage = (score: number, criticalVulns: number): string => {
        if (criticalVulns > 0) {
            return `⚠️ Alert! I've detected ${criticalVulns} critical vulnerability${criticalVulns > 1 ? 'ies' : 'y'} in your network. Your security score is ${score}/100. Would you like me to provide details?`;
        } else if (score >= 80) {
            return `🚨 Warning: Your network security score is ${score}/100 (high risk). I recommend running a full security analysis immediately.`;
        } else if (score >= 60) {
            return `⚠️ Your security score is ${score}/100 (moderate risk). There are some issues that need attention. How can I help?`;
        } else if (score >= 30) {
            return `Your network is looking stable with a security score of ${score}/100. I'm here to help with any security questions!`;
        } else {
            return `✅ Excellent! Your network security score is ${score}/100. Everything looks secure. Need help with anything?`;
        }
    };

    // Refresh security data periodically
    useEffect(() => {
        const interval = setInterval(fetchSecurityData, 60000); // Every 60s
        return () => clearInterval(interval);
    }, []);

    // Auto-scroll to bottom of messages
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    const toggleChat = () => {
        if (isOpen) {
            setChatAnimating(true);
            setTimeout(() => {
                setIsOpen(false);
                setChatAnimating(false);
            }, 150);
        } else {
            setIsOpen(true);
            setChatAnimating(true);
            setHasNewAlerts(false);
            setTimeout(() => setChatAnimating(false), 200);
        }
    };

    const handleSendMessage = async (customMessage?: string) => {
        const messageToSend = customMessage || inputValue.trim();
        if (!messageToSend || isThinking) return;

        const userMessage: Message = {
            id: Date.now().toString(),
            content: messageToSend,
            sender: 'user',
            timestamp: new Date()
        };

        setMessages(prev => [...prev, userMessage]);
        setInputValue('');
        setIsThinking(true);

        try {
            // Check for special commands
            const lowerMsg = messageToSend.toLowerCase();

            // Handle "Run Scan" - ask for confirmation first
            if (lowerMsg.includes('run scan') || lowerMsg.includes('start scan')) {
                const confirmMsg: Message = {
                    id: (Date.now() + 1).toString(),
                    content: "🔍 **Ready to scan your network!**\n\nI'll scan your WiFi network to:\n• Discover all connected devices\n• Categorize IoT vs Normal devices\n• Find vulnerabilities\n• Generate remediation steps\n\n**Would you like to proceed with the scan?**",
                    sender: 'bot',
                    timestamp: new Date(),
                    suggestions: ['Yes, start scanning', 'No, cancel']
                };
                setMessages(prev => [...prev, confirmMsg]);
            }
            // Handle scan confirmation
            else if (lowerMsg.includes('yes') && (lowerMsg.includes('scan') || lowerMsg.includes('start'))) {
                // User confirmed - run the Gemini-powered scan
                const startMsg: Message = {
                    id: (Date.now() + 1).toString(),
                    content: "🚀 **Scanning network with Gemini AI...**\n\nPlease wait while I:\n1. Discover all devices on your network\n2. Categorize them (IoT vs Normal)\n3. Check for vulnerabilities\n4. Generate security report\n\n⏳ This may take 30-60 seconds...",
                    sender: 'bot',
                    timestamp: new Date()
                };
                setMessages(prev => [...prev, startMsg]);
                setIsThinking(true);

                try {
                    const { data } = await aiAPI.geminiScanReport();

                    if (data.success) {
                        // Format the scan results
                        const summary = data.scanSummary;
                        const iotList = data.devices?.iot?.slice(0, 5).map((d: any) => `  • ${d.name} (${d.vendor || 'Unknown'}) - ${d.ip}`).join('\n') || '  None found';
                        const normalList = data.devices?.normal?.slice(0, 5).map((d: any) => `  • ${d.name} (${d.vendor || 'Unknown'}) - ${d.ip}`).join('\n') || '  None found';
                        const vulnList = data.vulnerabilities?.slice(0, 5).map((v: any) => `  • [${v.severity?.toUpperCase()}] ${v.title} on ${v.device}`).join('\n') || '  No vulnerabilities detected';

                        // Summary message
                        const summaryMsg: Message = {
                            id: (Date.now() + 2).toString(),
                            content: `✅ **Scan Complete!** (${summary?.scanDuration || 'N/A'})\n\n📊 **Summary:**\n• Total Devices: ${summary?.totalDevices || 0}\n• IoT Devices: ${summary?.iotDevices || 0}\n• Normal Devices: ${summary?.normalDevices || 0}\n• Vulnerabilities: ${summary?.vulnerabilities || 0}\n• Open Ports: ${summary?.openPorts || 0}\n\n🌐 **IoT Devices:**\n${iotList}\n\n💻 **Normal Devices:**\n${normalList}\n\n⚠️ **Vulnerabilities:**\n${vulnList}`,
                            sender: 'bot',
                            timestamp: new Date(),
                            suggestions: ['Show AI Report', 'Scan Again', 'Security Status']
                        };
                        setMessages(prev => [...prev, summaryMsg]);

                        // Store the AI report for later
                        (window as any).__lastGeminiReport = data.aiReport;
                    } else {
                        throw new Error(data.error || 'Scan failed');
                    }
                } catch (scanError: any) {
                    const errorMsg: Message = {
                        id: (Date.now() + 2).toString(),
                        content: `❌ **Scan Error**\n\n${scanError.message || 'Failed to complete network scan'}\n\nPlease make sure the backend is running and try again.`,
                        sender: 'bot',
                        timestamp: new Date(),
                        suggestions: ['Try Again', 'Security Status']
                    };
                    setMessages(prev => [...prev, errorMsg]);
                }
            }
            // Show AI Report
            else if (lowerMsg.includes('show ai report') || lowerMsg.includes('show report') || lowerMsg.includes('ai report')) {
                const aiReport = (window as any).__lastGeminiReport;
                if (aiReport) {
                    const reportMsg: Message = {
                        id: (Date.now() + 1).toString(),
                        content: `📝 **Gemini AI Security Report:**\n\n${aiReport}`,
                        sender: 'bot',
                        timestamp: new Date(),
                        suggestions: ['Run New Scan', 'Security Status']
                    };
                    setMessages(prev => [...prev, reportMsg]);
                } else {
                    const noReportMsg: Message = {
                        id: (Date.now() + 1).toString(),
                        content: "No AI report available yet. Would you like to run a network scan first?",
                        sender: 'bot',
                        timestamp: new Date(),
                        suggestions: ['Run Scan', 'Security Status']
                    };
                    setMessages(prev => [...prev, noReportMsg]);
                }
            }
            // Cancel scan
            else if (lowerMsg.includes('no') && lowerMsg.includes('cancel')) {
                const cancelMsg: Message = {
                    id: (Date.now() + 1).toString(),
                    content: "Okay, scan cancelled. Let me know if you need anything else!",
                    sender: 'bot',
                    timestamp: new Date(),
                    suggestions: ['Security Status', 'Help']
                };
                setMessages(prev => [...prev, cancelMsg]);
            }
            else if (lowerMsg.includes('security status') || lowerMsg.includes('status')) {
                // Fetch fresh security data first
                try {
                    const [scoreRes, alertsRes, threatsRes] = await Promise.allSettled([
                        securityAPI.getScore(),
                        alertAPI.getAll(),
                        threatAPI.getStats()
                    ]);

                    const freshScore = scoreRes.status === 'fulfilled' ? (scoreRes.value.data?.score ?? 50) : securityData.score;
                    const freshAlerts = alertsRes.status === 'fulfilled'
                        ? (Array.isArray(alertsRes.value.data) ? alertsRes.value.data.length : alertsRes.value.data?.length ?? 0)
                        : securityData.alerts;
                    const freshCritical = threatsRes.status === 'fulfilled' ? (threatsRes.value.data?.critical ?? 0) : securityData.criticalVulns;

                    // Update state with fresh data
                    setSecurityData({ score: freshScore, alerts: freshAlerts, criticalVulns: freshCritical, threats: freshAlerts });

                    // Determine network state based on score (lower score = more secure)
                    const networkState = freshScore >= 70 ? 'Critical 🔴'
                        : freshScore >= 50 ? 'At Risk 🟠'
                            : freshScore >= 30 ? 'Moderate 🟡'
                                : 'Stable 🟢';

                    const statusMsg: Message = {
                        id: (Date.now() + 1).toString(),
                        content: `📊 **Current Security Status:**\n\n🛡️ **Security Score:** ${freshScore}/100\n📡 **Network State:** ${networkState}\n🚨 **Active Alerts:** ${freshAlerts}\n⚠️ **Critical Issues:** ${freshCritical}\n\n${freshScore >= 50 ? '⚠️ Your network needs attention. Consider running a full scan.' : '✅ Your network appears stable. Continue monitoring.'}`,
                        sender: 'bot',
                        timestamp: new Date(),
                        suggestions: ['Run Scan', 'View Threats', 'Get Tips']
                    };
                    setMessages(prev => [...prev, statusMsg]);
                } catch {
                    const statusMsg: Message = {
                        id: (Date.now() + 1).toString(),
                        content: `📊 **Security Status (Cached):**\n• Score: ${securityData.score}/100\n• Active Alerts: ${securityData.alerts}\n• Critical Issues: ${securityData.criticalVulns}`,
                        sender: 'bot',
                        timestamp: new Date(),
                        suggestions: ['Run Scan', 'View Threats']
                    };
                    setMessages(prev => [...prev, statusMsg]);
                }
            } else if (lowerMsg.includes('view threat') || lowerMsg.includes('threats') || lowerMsg.includes('view alert') || lowerMsg.includes('alerts')) {
                // View Threats - fetch real-time alert data
                try {
                    const { data: alertsData } = await alertAPI.getAll();
                    const alertsList = Array.isArray(alertsData) ? alertsData : alertsData?.alerts || [];

                    if (alertsList.length === 0) {
                        const noThreatsMsg: Message = {
                            id: (Date.now() + 1).toString(),
                            content: '✅ **No Active Threats**\n\nYour network currently has no active alerts. Keep monitoring with regular scans.',
                            sender: 'bot',
                            timestamp: new Date(),
                            suggestions: ['Run Scan', 'Security Status']
                        };
                        setMessages(prev => [...prev, noThreatsMsg]);
                    } else {
                        // Show top threats with real data
                        const threatSummary = alertsList.slice(0, 5).map((a: any) =>
                            `• [${(a.severity || 'UNKNOWN').toUpperCase()}] ${a.title || a.message || 'Alert'} - Target: ${a.target_ip || a.device_ip || 'N/A'} (${a.acknowledged ? 'Resolved' : 'Active'})`
                        ).join('\n');

                        const criticalCount = alertsList.filter((a: any) => a.severity === 'critical').length;
                        const highCount = alertsList.filter((a: any) => a.severity === 'high').length;
                        const activeCount = alertsList.filter((a: any) => !a.acknowledged).length;

                        const threatsMsg: Message = {
                            id: (Date.now() + 1).toString(),
                            content: `🚨 **Active Threats (${activeCount} active, ${alertsList.length} total):**\n\n📊 **Severity Breakdown:**\n• Critical: ${criticalCount}\n• High: ${highCount}\n\n**Recent Alerts:**\n${threatSummary}\n\n${criticalCount > 0 ? '⚠️ Critical issues require immediate attention!' : ''}`,
                            sender: 'bot',
                            timestamp: new Date(),
                            suggestions: ['Run Scan', 'Get Tips', 'Security Status']
                        };
                        setMessages(prev => [...prev, threatsMsg]);
                    }
                } catch {
                    const errorMsg: Message = {
                        id: (Date.now() + 1).toString(),
                        content: "Couldn't fetch threat data. Please check the Intruder Feed page for real-time alerts.",
                        sender: 'bot',
                        timestamp: new Date(),
                        suggestions: ['Security Status', 'Run Scan']
                    };
                    setMessages(prev => [...prev, errorMsg]);
                }
            } else if (lowerMsg.includes('analyze') || lowerMsg.includes('network scan')) {
                // Trigger network analysis
                try {
                    const { data } = await aiAPI.analyzeNetwork();
                    const analysisMsg: Message = {
                        id: (Date.now() + 1).toString(),
                        content: `🔍 **Network Analysis Complete:**\n• Overall Risk: ${data.riskLevel?.toUpperCase() || 'UNKNOWN'}\n• Devices at Risk: ${data.devicesByRisk?.critical || 0} critical, ${data.devicesByRisk?.high || 0} high\n• Top Threats: ${data.topThreats?.slice(0, 3).map((t: any) => t.title).join(', ') || 'None detected'}\n\n${data.recommendations?.[0]?.message || 'Continue monitoring your network.'}`,
                        sender: 'bot',
                        timestamp: new Date(),
                        suggestions: ['More Details', 'Run Full Scan', 'View Recommendations']
                    };
                    setMessages(prev => [...prev, analysisMsg]);
                } catch {
                    const errorMsg: Message = {
                        id: (Date.now() + 1).toString(),
                        content: "I couldn't complete the network analysis right now. The backend service may need authentication. Try running a scan from the Scan Engine page.",
                        sender: 'bot',
                        timestamp: new Date(),
                        suggestions: ['Security Status', 'Help']
                    };
                    setMessages(prev => [...prev, errorMsg]);
                }
            } else if (lowerMsg.includes('recommend') || lowerMsg.includes('tips') || lowerMsg.includes('suggestion')) {
                // Get recommendations
                try {
                    const { data } = await aiAPI.getRecommendations();
                    const recList = data?.slice(0, 3).map((r: any) => `• ${r.title}: ${r.description}`).join('\n') || 'No specific recommendations at this time.';
                    const recMsg: Message = {
                        id: (Date.now() + 1).toString(),
                        content: `💡 **Security Recommendations:**\n${recList}`,
                        sender: 'bot',
                        timestamp: new Date(),
                        suggestions: ['Apply Fixes', 'Run Scan', 'View All']
                    };
                    setMessages(prev => [...prev, recMsg]);
                } catch {
                    // Context-aware fallback recommendations based on current security data
                    let contextTips = '💡 **Security Tips Based on Your Network:**\n\n';

                    if (securityData.criticalVulns > 0) {
                        contextTips += `🚨 **Critical Alert:** You have ${securityData.criticalVulns} critical issue(s).\n• Address critical vulnerabilities immediately\n• Check the Intruder Feed for details\n• Consider isolating affected devices\n\n`;
                    }

                    if (securityData.score >= 70) {
                        contextTips += '⚠️ **High Risk Network:**\n• Run a full network scan immediately\n• Review all open ports and close unnecessary ones\n• Update firmware on all IoT devices\n• Enable network segmentation if possible';
                    } else if (securityData.score >= 50) {
                        contextTips += '🟠 **Moderate Risk:**\n• Run regular scans (daily recommended)\n• Review recent alerts in Intruder Feed\n• Keep all device firmware updated\n• Monitor for unusual network traffic';
                    } else if (securityData.score >= 30) {
                        contextTips += '🟡 **Low-Moderate Risk:**\n• Continue weekly scans\n• Keep firmware updated\n• Review access controls regularly\n• Document your network devices';
                    } else {
                        contextTips += '🟢 **Good Standing:**\n• Maintain regular scan schedule\n• Keep firmware up to date\n• Monitor for new device connections\n• Review security policies periodically';
                    }

                    const fallbackMsg: Message = {
                        id: (Date.now() + 1).toString(),
                        content: contextTips,
                        sender: 'bot',
                        timestamp: new Date(),
                        suggestions: ['Run Scan', 'View Threats', 'Security Status']
                    };
                    setMessages(prev => [...prev, fallbackMsg]);
                }
            } else {
                // Use AI chat endpoint
                try {
                    const { data } = await aiAPI.chat(messageToSend, { securityScore: securityData.score });
                    const botMessage: Message = {
                        id: (Date.now() + 1).toString(),
                        content: data.message || "I'm here to help with security analysis and recommendations.",
                        sender: 'bot',
                        timestamp: new Date(),
                        suggestions: data.suggestions || []
                    };
                    setMessages(prev => [...prev, botMessage]);
                } catch {
                    // Intelligent fallback response
                    const fallbackResponse = generateFallbackResponse(messageToSend);
                    const fallbackMsg: Message = {
                        id: (Date.now() + 1).toString(),
                        content: fallbackResponse.message,
                        sender: 'bot',
                        timestamp: new Date(),
                        suggestions: fallbackResponse.suggestions
                    };
                    setMessages(prev => [...prev, fallbackMsg]);
                }
            }
        } catch (error) {
            const errorMessage: Message = {
                id: (Date.now() + 1).toString(),
                content: "I'm having trouble connecting. Please check if the backend is running.",
                sender: 'bot',
                timestamp: new Date()
            };
            setMessages(prev => [...prev, errorMessage]);
        } finally {
            setIsThinking(false);
        }
    };

    const generateFallbackResponse = (message: string): { message: string; suggestions: string[] } => {
        const lower = message.toLowerCase();

        if (lower.includes('vulnerab') || lower.includes('cve')) {
            return {
                message: "I can help analyze vulnerabilities in your network. Check the AI Report page for detailed device analysis, or run a network scan to discover new issues.",
                suggestions: ['Run Scan', 'View AI Report', 'Security Status']
            };
        } else if (lower.includes('scan')) {
            return {
                message: "You can initiate network scans from the Scan Engine page. I recommend running regular scans to detect new devices and vulnerabilities.",
                suggestions: ['Go to Scan Engine', 'Security Status']
            };
        } else if (lower.includes('alert') || lower.includes('threat')) {
            return {
                message: `Currently tracking ${securityData.alerts} alerts and ${securityData.criticalVulns} critical issues. Visit the Intruder Feed for real-time threat monitoring.`,
                suggestions: ['View Intruder Feed', 'Analyze Network']
            };
        } else if (lower.includes('help')) {
            return {
                message: "I can help you with:\n• Security status checks\n• Network analysis\n• Vulnerability insights\n• Security recommendations\n\nJust ask me anything!",
                suggestions: ['Security Status', 'Analyze Network', 'Get Recommendations']
            };
        }

        return {
            message: "I'm your AI security assistant. I can help with security analysis, threat detection, and recommendations. What would you like to know?",
            suggestions: ['Security Status', 'Run Scan', 'Help']
        };
    };

    const handleSuggestionClick = (suggestion: string) => {
        handleSendMessage(suggestion);
    };

    const handleKeyPress = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSendMessage();
        }
    };

    // Get emotion-specific colors for SVG
    const getEmotionColors = () => {
        switch (emotion) {
            case 'happy':
                return { primary: '#00ff88', secondary: '#00ffcc', eye: '#00ff88' };
            case 'neutral':
                return { primary: '#00d4ff', secondary: '#00ffff', eye: '#00d4ff' };
            case 'alert':
                return { primary: '#ffaa00', secondary: '#ffcc00', eye: '#ffaa00' };
            case 'critical':
                return { primary: '#ff4444', secondary: '#ff6666', eye: '#ff4444' };
        }
    };

    const colors = getEmotionColors();

    // 2D Mascot Character SVG
    const BotSVG = ({ size = 60 }: { size?: number }) => (
        <svg width={size} height={size} viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" className="bot-character-svg">
            <defs>
                <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="2" result="blur" />
                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
            </defs>

            {/* Hover/Float Group */}
            <g className="character-float-group">
                {/* Body Shadow */}
                <ellipse cx="50" cy="85" rx="20" ry="5" fill="#000" opacity="0.3" className="character-shadow" />

                {/* Main Body */}
                <rect x="30" y="30" width="40" height="40" rx="10" fill="#2D3748" stroke={colors.primary} strokeWidth="2" />
                <rect x="30" y="30" width="40" height="36" rx="10" fill="url(#body-gradient)" opacity="0.8" />

                {/* Screen/Face Area */}
                <rect x="35" y="38" width="30" height="22" rx="4" fill="#000" />

                {/* Eyes - Dynamic based on emotion */}
                <g className={`eyes-container ${emotion}`}>
                    {emotion === 'happy' && (
                        <>
                            <path d="M40 48 Q44 44 48 48" stroke={colors.primary} strokeWidth="2.5" strokeLinecap="round" fill="none" />
                            <path d="M52 48 Q56 44 60 48" stroke={colors.primary} strokeWidth="2.5" strokeLinecap="round" fill="none" />
                        </>
                    )}
                    {emotion === 'neutral' && (
                        <>
                            <circle cx="42" cy="48" r="3" fill={colors.eye} className="eye-blink" />
                            <circle cx="58" cy="48" r="3" fill={colors.eye} className="eye-blink" />
                        </>
                    )}
                    {emotion === 'alert' && (
                        <>
                            <circle cx="42" cy="48" r="4" fill={colors.primary} />
                            <circle cx="58" cy="48" r="4" fill={colors.primary} />
                            <line x1="38" y1="42" x2="46" y2="44" stroke={colors.primary} strokeWidth="1" />
                            <line x1="62" y1="42" x2="54" y2="44" stroke={colors.primary} strokeWidth="1" />
                        </>
                    )}
                    {emotion === 'critical' && (
                        <>
                            <path d="M38 46 L46 50" stroke={colors.primary} strokeWidth="2" strokeLinecap="round" />
                            <path d="M38 50 L46 46" stroke={colors.primary} strokeWidth="2" strokeLinecap="round" />
                            <path d="M54 46 L62 50" stroke={colors.primary} strokeWidth="2" strokeLinecap="round" />
                            <path d="M54 50 L62 46" stroke={colors.primary} strokeWidth="2" strokeLinecap="round" />
                        </>
                    )}
                </g>

                {/* Antenna */}
                <line x1="50" y1="30" x2="50" y2="20" stroke={colors.primary} strokeWidth="2" />
                <circle cx="50" cy="18" r="3" fill={colors.primary}>
                    <animate attributeName="opacity" values="1;0.4;1" dur={hasNewAlerts ? "0.5s" : "2s"} repeatCount="indefinite" />
                </circle>

                {/* Headphones/Ears */}
                <rect x="26" y="42" width="4" height="16" rx="2" fill={colors.secondary} />
                <rect x="70" y="42" width="4" height="16" rx="2" fill={colors.secondary} />
            </g>

            <defs>
                <linearGradient id="body-gradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#4A5568" />
                    <stop offset="100%" stopColor="#2D3748" />
                </linearGradient>
            </defs>
        </svg>
    );

    const getEmotionIcon = () => {
        switch (emotion) {
            case 'happy': return <Shield className="w-2.5 h-2.5" />;
            case 'neutral': return <Sparkles className="w-2.5 h-2.5" />;
            case 'alert': return <AlertTriangle className="w-2.5 h-2.5" />;
            case 'critical': return <Zap className="w-2.5 h-2.5" />;
        }
    };

    const getAlertBannerType = () => {
        if (securityData.criticalVulns > 0) return 'critical';
        if (securityData.score >= 70) return 'warning';
        if (securityData.score < 30) return 'success';
        return null;
    };

    const alertBannerType = getAlertBannerType();

    return (
        <div className="ai-bot-container">
            {/* Chat Panel */}
            {isOpen && (
                <div className={`ai-bot-chat-panel ${chatAnimating ? (isOpen ? 'chat-expanding' : 'chat-collapsing') : ''}`}>
                    {/* Header */}
                    <div className="chat-header">
                        <div className="chat-header-info">
                            <div className="chat-header-avatar">
                                <BotSVG size={32} />
                            </div>
                            <div className="chat-header-text">
                                <h3>CodeX AI</h3>
                                <span>{isThinking ? 'Analyzing...' : `Score: ${securityData.score}/100`}</span>
                            </div>
                        </div>
                        <div style={{ display: 'flex', gap: '4px' }}>
                            <button className="chat-close-btn" onClick={fetchSecurityData} title="Refresh">
                                <RefreshCw size={14} />
                            </button>
                            <button className="chat-close-btn" onClick={toggleChat}>
                                <X size={16} />
                            </button>
                        </div>
                    </div>

                    {/* Alert Banner */}
                    {alertBannerType && (
                        <div className={`chat-alert-banner ${alertBannerType === 'warning' ? 'warning' : alertBannerType === 'success' ? 'success' : ''}`}>
                            {alertBannerType === 'critical' && <><AlertTriangle size={12} /> {securityData.criticalVulns} critical issue{securityData.criticalVulns > 1 ? 's' : ''} detected</>}
                            {alertBannerType === 'warning' && <><AlertTriangle size={12} /> Network at elevated risk</>}
                            {alertBannerType === 'success' && <><Shield size={12} /> Network secure</>}
                        </div>
                    )}

                    {/* Messages */}
                    <div className="chat-messages">
                        {messages.map((msg) => (
                            <div key={msg.id}>
                                <div className={`chat-message chat-message-${msg.sender}`}>
                                    {msg.content.split('\n').map((line, i) => (
                                        <span key={i}>{line}<br /></span>
                                    ))}
                                </div>
                                {msg.sender === 'bot' && msg.suggestions && msg.suggestions.length > 0 && (
                                    <div className="chat-suggestions">
                                        {msg.suggestions.map((sug, i) => (
                                            <button key={i} className="suggestion-btn" onClick={() => handleSuggestionClick(sug)}>
                                                {sug}
                                            </button>
                                        ))}
                                    </div>
                                )}
                            </div>
                        ))}
                        {isThinking && (
                            <div className="chat-message chat-message-bot">
                                <div className="thinking-indicator">
                                    <span className="thinking-dot"></span>
                                    <span className="thinking-dot"></span>
                                    <span className="thinking-dot"></span>
                                </div>
                            </div>
                        )}
                        <div ref={messagesEndRef} />
                    </div>

                    {/* Quick Actions */}
                    <div className="quick-actions">
                        <button className="quick-action-btn" onClick={() => handleSendMessage('Security Status')}>
                            📊 Status
                        </button>
                        <button className="quick-action-btn" onClick={() => handleSendMessage('Analyze Network')}>
                            🔍 Analyze
                        </button>
                        <button className="quick-action-btn" onClick={() => handleSendMessage('Get Recommendations')}>
                            💡 Tips
                        </button>
                    </div>

                    {/* Input */}
                    <div className="chat-input-container">
                        <input
                            type="text"
                            className="chat-input"
                            placeholder="Ask about security..."
                            value={inputValue}
                            onChange={(e) => setInputValue(e.target.value)}
                            onKeyPress={handleKeyPress}
                            disabled={isThinking}
                        />
                        <button
                            className="chat-send-btn"
                            onClick={() => handleSendMessage()}
                            disabled={!inputValue.trim() || isThinking}
                        >
                            <Send size={16} />
                        </button>
                    </div>
                </div>
            )}

            {/* Bot Avatar */}
            <div
                className={`ai-bot-avatar 
          ${isAnimatingIn ? 'ai-bot-pop-in' : 'ai-bot-floating'} 
          ${isWaving ? 'ai-bot-waving' : ''} 
          ${isThinking ? 'ai-bot-thinking' : ''}
          ai-bot-${emotion}`}
                onClick={toggleChat}
                title="Click to chat with CodeX AI"
            >
                <BotSVG />
                {hasNewAlerts && !isOpen && <div className="notification-dot" />}
                <div className={`security-badge security-badge-${emotion}`}>
                    {getEmotionIcon()}
                </div>
            </div>
        </div>
    );
};

export default AIBot;
