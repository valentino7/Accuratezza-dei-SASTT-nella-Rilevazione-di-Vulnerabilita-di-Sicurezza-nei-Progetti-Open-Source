package entity;

import java.util.Arrays;

public class Rule {

    private String rule;
    private String file;
    private String bug;


    public String getBug() {
        return bug;
    }

    public void setBug(String bug) {
        this.bug = bug;
    }

    public String getRule() {
        return rule;
    }

    public void setRule(String rule) {
        this.rule = rule;
    }

    public String getFile() {
        return file;
    }

    public void setFile(String file) {
        this.file = file;
    }

    public Rule(String rule, String file, String bug) {
        super();
        this.rule = rule;
        this.file = file;
        this.bug = bug;

    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Rule r = (Rule) o;
        return Arrays.asList(rule, file, bug).equals(Arrays.asList(r.getRule(), r.getFile(), r.getBug()));
    }

}
