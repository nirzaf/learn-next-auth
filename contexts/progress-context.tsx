'use client';

import React, { createContext, useContext, useState, useEffect } from 'react';
import { useAuth } from './auth-context';

interface Achievement {
  id: string;
  title: string;
  description: string;
  points: number;
  unlockedAt: string;
}

interface PlaygroundProject {
  name: string;
  code: string;
  template: string;
  savedAt: string;
}

interface ProgressContextType {
  progress: Record<string, number>;
  achievements: Achievement[];
  updateModuleProgress: (moduleId: string, progress: number) => void;
  getModuleProgress: (moduleId: string) => number;
  getTotalProgress: () => number;
  unlockAchievement: (achievementId: string) => void;
  savePlaygroundCode: (name: string, code: string, template: string) => void;
  getSavedCode: () => PlaygroundProject[];
}

const ProgressContext = createContext<ProgressContextType | undefined>(undefined);

export function ProgressProvider({ children }: { children: React.ReactNode }) {
  const { user } = useAuth();
  const [progress, setProgress] = useState<Record<string, number>>({});
  const [achievements, setAchievements] = useState<Achievement[]>([]);
  const [savedCode, setSavedCode] = useState<PlaygroundProject[]>([]);

  // Load progress from localStorage when user changes
  useEffect(() => {
    if (user) {
      const savedProgress = localStorage.getItem(`progress_${user.id}`);
      const savedAchievements = localStorage.getItem(`achievements_${user.id}`);
      const savedPlayground = localStorage.getItem(`playground_${user.id}`);
      
      if (savedProgress) {
        setProgress(JSON.parse(savedProgress));
      }
      
      if (savedAchievements) {
        setAchievements(JSON.parse(savedAchievements));
      } else {
        // Initialize with first login achievement
        const firstLogin: Achievement = {
          id: 'first-login',
          title: 'Welcome Aboard!',
          description: 'Successfully logged into the learning platform',
          points: 25,
          unlockedAt: new Date().toISOString()
        };
        setAchievements([firstLogin]);
      }
      
      if (savedPlayground) {
        setSavedCode(JSON.parse(savedPlayground));
      }
    } else {
      setProgress({});
      setAchievements([]);
      setSavedCode([]);
    }
  }, [user]);

  // Save progress to localStorage whenever it changes
  useEffect(() => {
    if (user && Object.keys(progress).length > 0) {
      localStorage.setItem(`progress_${user.id}`, JSON.stringify(progress));
    }
  }, [progress, user]);

  useEffect(() => {
    if (user && achievements.length > 0) {
      localStorage.setItem(`achievements_${user.id}`, JSON.stringify(achievements));
    }
  }, [achievements, user]);

  useEffect(() => {
    if (user && savedCode.length > 0) {
      localStorage.setItem(`playground_${user.id}`, JSON.stringify(savedCode));
    }
  }, [savedCode, user]);

  const updateModuleProgress = (moduleId: string, newProgress: number) => {
    setProgress(prev => {
      const updated = { ...prev, [moduleId]: Math.max(prev[moduleId] || 0, newProgress) };
      
      // Check for achievements
      checkAchievements(moduleId, newProgress, updated);
      
      return updated;
    });
  };

  const checkAchievements = (moduleId: string, moduleProgress: number, allProgress: Record<string, number>) => {
    const newAchievements: Achievement[] = [];
    
    // Module completion achievements
    if (moduleProgress === 100) {
      const moduleAchievements: Record<string, { id: string; title: string; description: string; points: number }> = {
        'getting-started': {
          id: 'fundamentals-master',
          title: 'Fundamentals Master',
          description: 'Completed Authentication Fundamentals',
          points: 50
        },
        'jwt-auth': {
          id: 'jwt-expert',
          title: 'JWT Expert',
          description: 'Mastered JWT Authentication',
          points: 100
        },
        'session-auth': {
          id: 'session-pro',
          title: 'Session Pro',
          description: 'Completed Session Authentication',
          points: 100
        },
        'oauth-auth': {
          id: 'oauth-specialist',
          title: 'OAuth Specialist',
          description: 'Mastered OAuth Integration',
          points: 150
        },
        'protected-routes': {
          id: 'security-guard',
          title: 'Security Guard',
          description: 'Expert in Protected Routes',
          points: 125
        },
        'advanced-security': {
          id: 'security-expert',
          title: 'Security Expert',
          description: 'Mastered Advanced Security',
          points: 200
        }
      };
      
      const achievement = moduleAchievements[moduleId];
      if (achievement && !achievements.find(a => a.id === achievement.id)) {
        newAchievements.push({
          ...achievement,
          unlockedAt: new Date().toISOString()
        });
      }
    }
    
    // Overall progress achievements
    const totalProgress = getTotalProgress(allProgress);
    if (totalProgress >= 50 && !achievements.find(a => a.id === 'halfway-hero')) {
      newAchievements.push({
        id: 'halfway-hero',
        title: 'Halfway Hero',
        description: 'Reached 50% overall progress',
        points: 75,
        unlockedAt: new Date().toISOString()
      });
    }
    
    if (totalProgress === 100 && !achievements.find(a => a.id === 'auth-master')) {
      newAchievements.push({
        id: 'auth-master',
        title: 'Authentication Master',
        description: 'Completed all modules with 100% progress',
        points: 500,
        unlockedAt: new Date().toISOString()
      });
    }
    
    if (newAchievements.length > 0) {
      setAchievements(prev => [...prev, ...newAchievements]);
    }
  };

  const getModuleProgress = (moduleId: string) => {
    return progress[moduleId] || 0;
  };

  const getTotalProgress = (progressData?: Record<string, number>) => {
    const data = progressData || progress;
    const modules = ['getting-started', 'jwt-auth', 'session-auth', 'oauth-auth', 'protected-routes', 'advanced-security'];
    const totalProgress = modules.reduce((sum, module) => sum + (data[module] || 0), 0);
    return Math.round(totalProgress / modules.length);
  };

  const unlockAchievement = (achievementId: string) => {
    // This can be used for manual achievement unlocking
    const predefinedAchievements: Record<string, { title: string; description: string; points: number }> = {
      'code-warrior': {
        title: 'Code Warrior',
        description: 'Saved 10 playground projects',
        points: 100
      },
      'security-researcher': {
        title: 'Security Researcher',
        description: 'Found a security vulnerability',
        points: 150
      }
    };
    
    const achievement = predefinedAchievements[achievementId];
    if (achievement && !achievements.find(a => a.id === achievementId)) {
      setAchievements(prev => [...prev, {
        id: achievementId,
        ...achievement,
        unlockedAt: new Date().toISOString()
      }]);
    }
  };

  const savePlaygroundCode = (name: string, code: string, template: string) => {
    const project: PlaygroundProject = {
      name,
      code,
      template,
      savedAt: new Date().toISOString()
    };
    
    setSavedCode(prev => {
      const updated = [project, ...prev.slice(0, 9)]; // Keep only 10 most recent
      
      // Check for code warrior achievement
      if (updated.length >= 5 && !achievements.find(a => a.id === 'code-warrior')) {
        unlockAchievement('code-warrior');
      }
      
      return updated;
    });
  };

  const getSavedCode = () => {
    return savedCode;
  };

  return (
    <ProgressContext.Provider value={{
      progress,
      achievements,
      updateModuleProgress,
      getModuleProgress,
      getTotalProgress,
      unlockAchievement,
      savePlaygroundCode,
      getSavedCode
    }}>
      {children}
    </ProgressContext.Provider>
  );
}

export function useProgress() {
  const context = useContext(ProgressContext);
  if (context === undefined) {
    throw new Error('useProgress must be used within a ProgressProvider');
  }
  return context;
}