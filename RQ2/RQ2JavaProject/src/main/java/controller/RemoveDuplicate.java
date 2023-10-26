package controller;

import entity.Rule;
import utils.Constants;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;

import static IO.ReaderInputs.getAbsolute;
import static IO.WriterResults.printWriter;

public class RemoveDuplicate {
    public static ArrayList<Rule> readPluginResults(String path) throws IOException {
        String line = "";
        String splitBy = ";";

        ArrayList<Rule> rules = new ArrayList<Rule>();

        BufferedReader br = new BufferedReader(new FileReader(getAbsolute(path)));

        while ((line = br.readLine()) != null)   //returns a Boolean value
        {

            String[] l = line.split(splitBy);    // use comma as separator

            // rule, file, bug
            Rule r = new Rule(l[1], l[0], l[2]);

            int found = 0;
            for (Rule tmp : rules) {
                if (tmp.getFile().equals(l[0]) && tmp.getBug().equals(l[2]) && tmp.getRule().equals(l[1])) {
                    found = 1;
                    break;
                }
            }
            if (found == 0)
                rules.add(r);
        }
        return rules;
    }

    public static void main(String args[]) throws IOException {
        PrintWriter writer = new PrintWriter(getAbsolute(Constants.ROOT_PATH_PARSING_REPORT+"filePMD2Removed.csv"));

        String line = "";
        String splitBy = ";";

        ArrayList<Rule> rules = new ArrayList<Rule>();
        BufferedReader br = new BufferedReader(new FileReader(getAbsolute(Constants.ROOT_PATH_PARSING_REPORT+"filePMD2old.csv")));
        while ((line = br.readLine()) != null)   //returns a Boolean value
        {
            String[] l = line.split(splitBy);    // use comma as separator

            // rule, file, bug
            Rule r = new Rule(l[1], l[0], l[2]);
            int found = 0;
            for (Rule r1: rules){
                if (r1.getRule().equals(r.getRule()) && r1.getBug().equals(r.getBug()) && r1.getFile().equals(r.getFile())){
                    found = 1;
                    break;
                }
            }
            if (found==0) {
                rules.add(r);
                System.err.println(l[0]);

                printWriter(writer, l);
            }
        }
    }
}