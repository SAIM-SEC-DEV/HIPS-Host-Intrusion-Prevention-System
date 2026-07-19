package com.hips.agent.process;

import java.time.LocalDateTime;

/**
 * Data model for an active process.
 */
public class ProcessInfo {
    private int pid;
    private int parentPid;
    private String name;
    private String parentName;
    private String commandLine;
    private String executablePath;
    private String user;
    private LocalDateTime startTime;

    public ProcessInfo(int pid, String name) {
        this.pid = pid;
        this.name = name;
        this.startTime = LocalDateTime.now();
    }

    // Getters
    public int getPid() { return pid; }
    public int getParentPid() { return parentPid; }
    public String getName() { return name; }
    public String getParentName() { return parentName; }
    public String getCommandLine() { return commandLine; }
    public String getExecutablePath() { return executablePath; }
    public String getUser() { return user; }
    public LocalDateTime getStartTime() { return startTime; }

    // Setters
    public void setParentPid(int parentPid) { this.parentPid = parentPid; }
    public void setParentName(String parentName) { this.parentName = parentName; }
    public void setCommandLine(String commandLine) { this.commandLine = commandLine; }
    public void setExecutablePath(String executablePath) { this.executablePath = executablePath; }
    public void setUser(String user) { this.user = user; }

    @Override
    public String toString() {
        return String.format("[%d] %s (Parent: %d %s)", pid, name, parentPid, parentName != null ? parentName : "Unknown");
    }
}
