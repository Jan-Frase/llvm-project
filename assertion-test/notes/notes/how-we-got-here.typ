Grundidee war auf Blesel Plugin aufbauend einen Check für unsafe Buffer writes einzubauen.
Darin habe ich mich dann eingearbeitet und von selber von Grund auf ein eigenes Plugin geschrieben.
Da habe ich dann auch versucht eigene Algorithmen zu schreiben um über den CFG zu traversieren und zu überprüfen ob in mindesten einem Fall der Buffer verändert wird bevor ein passendes wait erreicht wird.
Dabei ist mir aufgefallen dass das ziemlich schwer ist und habe ein paar Papern überflogen.
Da der MPI-Checker ähnliche Probleme lösen muss habe ich dann da geguckt.
Dann habe ich dem MPI-Checker meinen Check hinzugefügt und das ganze hat gut geklappt.
Um diese Technik für ähnliche Libs verfügbar zu machen habe ich dann Annotations eingebaut. 
Jetzt probiere ich ein Macro aus um das einbinden der Annotationen zu automatisieren.
