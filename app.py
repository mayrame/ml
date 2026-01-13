import streamlit as st
import pefile
import joblib
import os

#La fonction pefile pour extraire 
def extract_features(exe_path):
    pe = pefile.PE(exe_path)
    
    # Extraction des 8 caractéristiques demandées
    features = [
        pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        pe.OPTIONAL_HEADER.MajorLinkerVersion,
        pe.OPTIONAL_HEADER.MajorImageVersion,
        pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        pe.OPTIONAL_HEADER.DllCharacteristics,
        pe.OPTIONAL_HEADER.SizeOfStackReserve,
        pe.FILE_HEADER.NumberOfSections,
        #  ResourceSize permet de calculer la taille de la section ressources
        sum([section.SizeOfRawData for section in pe.sections if b'.rsrc' in section.Name])
    ]
    return features

#  STREAMLIT (l'applis)
st.title("Analyseur de Malware")
st.write("Déposez un fichier .exe pour savoir s'il est malveillant.")

#  On charge le modèle 
model = joblib.load('model.pkl')

uploaded_file = st.file_uploader("Choisir un exécutable...", type=["exe"])

if uploaded_file is not None:
    # Sauvegarde temporaire du fichier
    with open("temp.exe", "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    try:
        #On cree la variable data pour extraire les features
        data = extract_features("temp.exe")
        
        #Prédiction 
        prediction = model.predict([data])
        
        #Résultat
        if prediction[0] == 1:
            st.success(" RÉSULTAT : Ce fichier est LEGITIMATE")
        else:
            st.error("RÉSULTAT : Ce fichier est un MALWARE")
            
    except Exception as e:
        st.error(f"Erreur d'analyse : {e}")
    finally:
        if os.path.exists("temp.exe"):
            os.remove("temp.exe")