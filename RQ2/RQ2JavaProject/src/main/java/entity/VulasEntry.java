package entity;

import java.util.ArrayList;

public class VulasEntry {
    private ArrayList<String> cVeids;
    private String projectUrl;
    private String fixCommit;
    private String commitID;
    private String javaVersion;
    private String pomJDKVersion;
    private String command;
    private String output;
    private String isCompilable;

    public VulasEntry() {
        this.cVeids=new ArrayList<>();
    }

    public ArrayList<String> getcVeids() {
        return cVeids;
    }

    public void setcVeids(ArrayList<String> cVeids) {
        this.cVeids = cVeids;
    }

    public String getFixCommit() {
        return fixCommit;
    }

    public void setFixCommit(String fixCommit) {
        this.fixCommit = fixCommit;
    }

    public String getPomJDKVersion() {
        return pomJDKVersion;
    }

    public void setPomJDKVersion(String pomJDKVersion) {
        this.pomJDKVersion = pomJDKVersion;
    }

    public String getOutput() {
        return output;
    }

    public void setOutput(String output) {
        this.output = output;
    }

    public String getIsCompilable() {
        return isCompilable;
    }

    public void setIsCompilable(String isCompilable) {
        this.isCompilable = isCompilable;
    }

    public String getJavaVersion() {
        return javaVersion;
    }

    public void setJavaVersion(String javaVersion) {
        this.javaVersion = javaVersion;
    }

    public ArrayList<String> getCveids() {
        return cVeids;
    }

    public void setCveids(ArrayList<String> cveids) {
        this.cVeids = cveids;
    }

    public String getProjectUrl() {
        return projectUrl;
    }

    public void setProjectUrl(String projectUrl) {
        this.projectUrl = projectUrl;
    }

    public String getCommitID() {
        return commitID;
    }

    public void setCommitID(String commitID) {
        this.commitID = commitID;
    }

    public String getCommand() {
        return command;
    }

    public void setCommand(String command) {
        this.command = command;
    }
}
