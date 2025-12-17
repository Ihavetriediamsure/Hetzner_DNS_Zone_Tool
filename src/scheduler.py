"""Background task scheduler"""

import asyncio
from typing import Optional, Callable
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger


class TaskScheduler:
    """Background task scheduler for periodic updates"""
    
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self._running = False
    
    def start(self):
        """Start the scheduler"""
        if not self._running:
            self.scheduler.start()
            self._running = True
    
    def stop(self):
        """Stop the scheduler"""
        if self._running:
            self.scheduler.shutdown()
            self._running = False
    
    def schedule_job(self, func: Callable, interval_minutes: int, **kwargs):
        """Schedule a periodic job"""
        trigger = IntervalTrigger(minutes=interval_minutes)
        self.scheduler.add_job(func, trigger=trigger, **kwargs)
    
    def is_running(self) -> bool:
        """Check if scheduler is running"""
        return self._running


# Global instance
_task_scheduler = None


def get_task_scheduler() -> TaskScheduler:
    """Get global task scheduler instance"""
    global _task_scheduler
    if _task_scheduler is None:
        _task_scheduler = TaskScheduler()
    return _task_scheduler

