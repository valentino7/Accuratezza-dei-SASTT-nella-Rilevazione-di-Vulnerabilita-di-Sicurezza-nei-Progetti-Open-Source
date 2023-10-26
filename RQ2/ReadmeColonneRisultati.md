
Forniamo di seguito una breve sintesi delle colonne dell' Intermediate Result:

    CWE-ID: valore del CWE ricavato da OSS. Quando la Badness è False ovvero parliamo di un metodo Good questo campo viene valorizzato con il CWE risolto nella fix commit. Nel caso di metodi Bad viene valorizzato con il valore della vulnerabilità presente nella parent commit.,

    Project-Name: valorizzato con il nome del progetto,
    
    Method-Id: valorizzato con la stringa formata nel modo seguente: {pathClasseJava}+{$}+{nomeMetodo},
    
    Fix Commit: valorizzato con l'id della fix commit,
    
    Parent Commit: valorizzato con l'id della commit precedente alla fix commit. Non viene valorizzato quando il file proviene dal progetto della fix commit,
    
    Badness: valorizzato con True se il metodo proviene dalla parent commit False altrimenti,
    
    Size: dimensione in termini di numero di righe del metodo,
    
    Start: riga di inizio del metodo nella classe Java,
    
    End: riga di fine del metodo nella classe Java.



Forniamo di seguito una breve sintesi delle colonne del Final Result:

    CWE-ID: valore del CWE in OSS,
    
    Project-Name: valorizzato con il nome del progetto,
    
    Method-Id: valorizzato con la stringa formata nel modo seguente: {pathClasseJava}+{$}+{nomeMetodo},
    
    Fix Commit: valorizzato con l'id della fix commit,
    
    Badness: valorizzato con True se il metodo \`e Bad e proviene dalla parent commit e False se Good,
    
    SASTT-Id: valorizzato con il nome del SASTT,
    
    SASTT Result: Contiene il CWE o l'insieme dei CWE identificati dal SASTT sul metodo in esame, viene valorizzato con ``??" se il SASTT non \`e in grado di rilevare il CWE-ID, ovvero il CWE-ID nella prima colonna non \`e presente nella lista degli ECWE del SASTT,
    
    Size: valorizzato con la dimensione in termini di numero di righe del metodo in esame,
    
    TP: valorizzato come descritto nel flusso della tesi,
    
    TN: valorizzato come descritto nel flusso della tesi,
    
    FP: valorizzato come descritto nel flusso della tesi,
    
    FN : valorizzato come descritto nel flusso della tesi.
