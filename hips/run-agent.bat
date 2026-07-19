@echo off
TITLE HIPS Security Agent
echo Starting HIPS Security Agent...
java -cp "agent/bin;agent/lib/gson-2.10.1.jar" com.hips.agent.HipsAgent
pause
