# Ransomware Detection Project Team AD

Omschrijving:
Ransomware/Malware Detectie Project voor het vak Project Security. Door statische analyze van de md5 hashes van alle runnende programmas, wordt er gekeken of het malware is of niet door het te vergelijken met de database van alienvaultOTX. Als er gedetecteerd wordt dat er malware is, wordt dit opgeslagen in een database met de locatie, wordt het process gesloten, en de file verwijdered. Het programma is getest voor op een linux omgeving.

Gebruiksuitleg:
1. #### Creeer en virtual python omgeving. 
    ```python -m venv venv```

2. #### Activeer de enviroment.
    ```source venv/bin/activate```

3. #### Download de requirements
    ```pip download -r requirements.txt```

4. #### Run programma als sudo
