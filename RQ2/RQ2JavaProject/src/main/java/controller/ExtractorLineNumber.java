package controller;

import com.github.javaparser.Position;
import entity.FileTrack;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.util.Optional;

public class ExtractorLineNumber {

    public static void main(String[] args) throws ParseException, IOException {
        File f = new File(".").getAbsoluteFile();
        File srcRoot = new File(f, "src\\main\\java\\Prov.java");

        //getMethodLineNumbers(srcRoot);
    }

    public static FileTrack getMethodLineNumbers(File root, String f, FileTrack fTrack) throws ParseException, IOException {

        CompilationUnit cu;
        try {
            cu = StaticJavaParser.parse(new File(root, f));
        }catch (Exception e){
            return null;
        }
        //entity.FileTrack myPosition;
        //myPosition = new entity.FileTrack();
        new MethodVisitor().visit(cu, fTrack);
        fTrack.gethMethodPosition().remove("");
        return fTrack;
    }


    public static void runVisit(Optional<Position> begin, Optional<Position> end, String nameAsString, Object entry){
        Integer startModifiedLine = ((FileTrack)entry).gethMethodPosition().get("").getLineBegin();
        Integer endModifiedLine = ((FileTrack)entry).gethMethodPosition().get("").getLineEnd();
        String t = ((FileTrack)entry).gethMethodPosition().get("").getChangeType();
        System.out.println("inizio riga modificata"+String.valueOf(startModifiedLine));
        System.out.println("inizio metodo "+begin.get().line);
        System.out.println("fine metodo "+ end.get().line);
        System.out.println(t);
        if (startModifiedLine >= begin.get().line && startModifiedLine <= end.get().line){
            System.err.println("MATCH");
            ((FileTrack)entry).gethMethodPosition().get("").setLineBegin(begin.get().line);
            ((FileTrack)entry).gethMethodPosition().get("").setLineEnd(end.get().line);
            ((FileTrack)entry).gethMethodPosition().put(nameAsString, ((FileTrack)entry).gethMethodPosition().get(""));
        }
        /**
         * Caso in cui nella nuova commit vengono uniti due COSTRUTTORI in uno
         */
        else if(startModifiedLine >= begin.get().line && !(startModifiedLine <= end.get().line)){
            for (int i = 0; i!=endModifiedLine; i++){
                if (startModifiedLine+i >= begin.get().line && startModifiedLine+i <= end.get().line){
                    System.err.println("MATCH caso 2");
                    ((FileTrack)entry).gethMethodPosition().get("").setLineBegin(begin.get().line);
                    ((FileTrack)entry).gethMethodPosition().get("").setLineEnd(end.get().line);
                    ((FileTrack)entry).gethMethodPosition().put(nameAsString, ((FileTrack)entry).gethMethodPosition().get(""));
                }
            }
        }
    }

    /**
     * Simple visitor implementation for visiting MethodDeclaration nodes.
     */
    public static class MethodVisitor extends VoidVisitorAdapter {
        @Override
        public void visit(ConstructorDeclaration m, Object entry) {
            runVisit(m.getBegin(), m.getEnd(), m.getNameAsString(), entry);
        }
        @Override
        public void visit(MethodDeclaration m, Object entry) {

            /*System.out.println("From [" + m.getBegin().get() );
            System.out.println(m.getDeclarationAsString());
            //System.out.println(m);
            System.out.println(m.getName());
            System.out.println(m.getBegin().get().line);
            System.out.println(m.getBegin().get().column);
            System.out.println(m.getRange().get().begin);
            System.out.println(m.getRange().get().end);
            System.out.println(m.getEnd().get().line);

            System.out.println(((entity.FileTrack)entry).gethMethodPosition().get(""));*/
            runVisit(m.getBegin(), m.getEnd(), m.getNameAsString(), entry);

        }
    }
}