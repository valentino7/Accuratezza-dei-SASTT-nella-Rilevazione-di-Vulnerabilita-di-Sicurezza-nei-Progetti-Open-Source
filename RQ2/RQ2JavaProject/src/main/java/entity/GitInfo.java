package entity;

public class GitInfo {
    private Integer lineBegin;
    private Integer lineEnd;
    private String changeType;

    public GitInfo(Integer line, Integer lineEnd) {
        this.lineBegin = line;
        this.lineEnd = lineEnd;
    }

    public String getChangeType() {
        return changeType;
    }

    public void setChangeType(String changeType) {
        this.changeType = changeType;
    }

    public Integer getLineBegin() {
        return lineBegin;
    }

    public void setLineBegin(Integer line) {
        this.lineBegin = line;
    }

    public Integer getLineEnd() {
        return lineEnd;
    }

    public void setLineEnd(Integer lineEnd) {
        this.lineEnd = lineEnd;
    }
}
