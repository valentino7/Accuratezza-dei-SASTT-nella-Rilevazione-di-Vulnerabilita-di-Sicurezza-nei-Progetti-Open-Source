
import pandas as pd
import numpy as np

# Leggi il file CSV
df = pd.read_csv('union_result.csv')
print(df.head)
# Sostituisci gli spazi vuoti con NaN
df.replace('', np.nan, inplace=True)

# Rimuovi le colonne senza informazioni (colonne con solo NaN)
df = df.dropna(axis=1, how='all')

# Salva il DataFrame senza le colonne vuote in un nuovo file CSV
df.to_csv('Result_RQ3.csv', index=False)