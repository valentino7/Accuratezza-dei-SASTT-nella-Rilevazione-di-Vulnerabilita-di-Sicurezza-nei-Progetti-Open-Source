package entity;

import java.util.HashMap;

public class FileTrack {
    private String fileName;

    private String projectName;
    private HashMap<String, GitInfo> hMethodPosition;
    // False is Good and True is Bad
    private Boolean badness;
    private String toolResult;
    private String tooldID;

    private String CWE;

    private String FixCommitID;
    private String parentCommit;

    private String tp;
    private String fp;
    private String tn;
    private String fn;

    public String getTp() {
        return tp;
    }

    public void setTp(String tp) {
        this.tp = tp;
    }

    public String getFp() {
        return fp;
    }

    public void setFp(String fp) {
        this.fp = fp;
    }

    public String getTn() {
        return tn;
    }

    public void setTn(String tn) {
        this.tn = tn;
    }

    public String getFn() {
        return fn;
    }

    public void setFn(String fn) {
        this.fn = fn;
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public String getParentCommit() {
        return parentCommit;
    }

    public void setParentCommit(String parentCommit) {
        this.parentCommit = parentCommit;
    }

    public String getToolResult() {
        return toolResult;
    }

    public void setToolResult(String toolResult) {
        this.toolResult = toolResult;
    }

    public FileTrack() {
        hMethodPosition = new HashMap<>();
    }

    public String getTooldID() {
        return tooldID;
    }

    public void setTooldID(String tooldID) {
        this.tooldID = tooldID;
    }

    public HashMap<String, GitInfo> gethMethodPosition() {
        return hMethodPosition;
    }

    public void sethMethodPosition(HashMap<String, GitInfo> hMethodPosition) {
        this.hMethodPosition = hMethodPosition;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public Boolean getBadness() {
        return badness;
    }

    public void setBadness(Boolean badness) {
        this.badness = badness;
    }

    public String getFixCommitID() {
        return FixCommitID;
    }

    public void setFixCommitID(String fixCommitID) {
        FixCommitID = fixCommitID;
    }

    public String getCWE() {
        return CWE;
    }

    public void setCWE(String CWE) {
        this.CWE = CWE;
    }
}
