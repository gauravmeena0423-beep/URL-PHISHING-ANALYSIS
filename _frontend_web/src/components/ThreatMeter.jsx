import { useEffect, useState } from 'react';

export default function ThreatMeter({ score = 0 }) {
    const [animatedScore, setAnimatedScore] = useState(0);

    useEffect(() => {
        const timer = setTimeout(() => {
            setAnimatedScore(Number(score) || 0);
        }, 150);
        return () => clearTimeout(timer);
    }, [score]);

    // Color Logic
    const color = animatedScore >= 70 ? '#f43f5e' : animatedScore >= 40 ? '#f59e0b' : '#10b981';
    const glowColor = animatedScore >= 70 ? 'rgba(244, 63, 94, 0.45)' : animatedScore >= 40 ? 'rgba(245, 158, 11, 0.45)' : 'rgba(16, 185, 129, 0.45)';

    // SVG Circle Math
    const radius = 65;
    const circumference = 2 * Math.PI * radius;
    const strokeDashoffset = circumference - (Math.min(Math.max(animatedScore, 0), 100) / 100) * circumference;

    return (
        <div className="flex flex-col items-center justify-center p-6 w-full">
            <div className="relative flex items-center justify-center">
                {/* Background Circle */}
                <svg className="w-48 h-48 transform -rotate-90">
                    <circle
                        cx="96" cy="96" r={radius}
                        stroke="currentColor" strokeWidth="12" fill="transparent"
                        className="text-slate-800"
                    />
                    {/* Animated Progress Circle */}
                    <circle
                        cx="96" cy="96" r={radius}
                        stroke={color} strokeWidth="12" fill="transparent"
                        strokeDasharray={circumference}
                        strokeDashoffset={strokeDashoffset}
                        strokeLinecap="round"
                        className="transition-all duration-1000 ease-out"
                        style={{ filter: `drop-shadow(0 0 10px ${glowColor})` }}
                    />
                </svg>
                {/* Center Text */}
                <div className="absolute flex flex-col items-center justify-center text-center">
                    <span className="text-4xl font-black font-mono tracking-tight" style={{ color: color }}>
                        {animatedScore}%
                    </span>
                    <span className="text-xs tracking-widest text-slate-400 mt-1 uppercase font-semibold">
                        Threat Score
                    </span>
                </div>
            </div>
        </div>
    );
}