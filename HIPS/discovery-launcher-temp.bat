@echo off 
cd /D "%~dp0" 
java -cp "agent\bin;agent\lib\gson-2.10.1.jar" com.hips.agent.core.ServerDiscovery "http://192.168.56.1/hips" 
