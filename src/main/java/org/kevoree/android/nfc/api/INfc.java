package org.kevoree.android.nfc.api;


import android.content.Intent;

public interface INfc {

    // ///////////////////////////////////////////////////////////////

    // Fonctions écritures sur la puce NFC

    // ///////////////////////////////////////////////////////////////
    /**
     * Ecrire des données sur un block d'un secteur de la puce. (16 bytes)
     *
     * @param sector : dans lequel on veut écrire
     * @param block : dans lequel on souhaite écrire
     * @param data : données que l'on souhaite écrire
     * @param key : clé permettant l'authentification pour écrire
     * @param useAsKeyB : true si on utilise la keyB false sinon
     * @return true si les données on bien été transmise
     */
    public boolean writeInABlock(int sector, int block, String data, byte[] key, boolean useAsKeyB) throws TagActionException;

    /**
     * Ecrire dans un secteur de la puce NFC MifareClassic On peut écrire 32 bytes dans le secteur 1 (blocs 1 et 2) et 48 bytes dans les autres
     * secteurs (blocs 0, 1 et 2)
     *
     * @param sector : Secteur dans lequel on souhaite entrer de la data
     * @param data : information à écrire sur la puce
     * @param key : Clé permettant l'authentification au secteur
     * @param useAsKeyB : Si la clé utilisé est la clé A (false) ou la clé B (true)
     * @return true si les données on bien été transmise
     */
    public boolean writeInASector(int sector, String data, byte[] key, boolean useAsKeyB)throws TagActionException;

    /**
     * Ecire dans tout l'espace de la puce NFC (752bytes pour la MifareClassic 1K) Pour cette fonction il faut que tout les secteurs ont la même Key
     *
     * @param data : Données à transmettre
     * @param key : clé permettant l'authentification pour écrire
     * @param useAsKeyB : true si on utilise la keyB false sinon
     * @return true si les données on bien été transmise
     */
    public boolean writeInAllDataSpace(String data, byte[] key, boolean useAsKeyB)throws TagActionException;

    /**
     * Ecriture de la clé A en utilisant la clé A et la clé B
     *
     * @param sector : Sector dont on veut changer la clé A
     * @param keyA : Clé A actuelle
     * @param keyB : Clé B actuelle
     * @param newKeyA : nouvelle Clé A
     * @return true si les données on bien été transmise
     * @throws TagActionException
     */
    public boolean writeKeyA(int sector,  byte[] keyA, byte[] keyB, byte[] newKeyA) throws TagActionException;

    /**
     * Ecriture de la clé B en utilisant la clé A et la clé B
     *
     * @param sector : Sector dont on veut changer la clé B
     * @param keyA : Clé A actuelle
     * @param keyB : Clé B actuelle
     * @param newKeyB : nouvelle CléB
     * @return true si les données on bien été transmise
     * @throws TagActionException
     */
    public boolean writeKeyB(int sector, byte[] keyA, byte[] keyB, byte[] newKeyB) throws TagActionException;

    /**
     * Ecriture des AccesBits du Sector Trailer
     *
     * @param sector : numéro du secteur dont on souhaite changer les AccessBits
     * @param keyA : Key A actuelle
     * @param keyB : Key B actuelle
     * @param newAccessBit : Nouveau AccesBits du SectorTrailer
     * @return true si l'écriture c'est bien passé
     * @throws TagActionException : Action non permise
     */
    public boolean writeAccesBit(int sector, byte[] keyA, byte[] keyB, byte[] newAccessBit) throws TagActionException;


    // ///////////////////////////////////////////////////////////////

    // Fonctions lectures sur la puce NFC

    // ///////////////////////////////////////////////////////////////

    /**
     * Obtenir le Numéro ID du tag
     *
     * @return ID du TAG (String)
     */
    public String getId();

    /**
     * Récupère le nombre de bloc dans le TAG NFC
     *
     * @return nombre de block de la puce NFC
     */
    public int getBlockCount();

    /**
     * Récupère le nombre de block dans le secteur en paramètre du tag NFC
     *
     * @param sector : index du secteur dont on souhaite connaitre le nombre de bloc
     * @return le nombre de bloc dans le secteur demandé
     */
    public int getBlockCountInSector(int sector);

    /**
     * Récupère le nombre de secteur du tag NFC
     *
     * @return nombre de secteur dans la puce NFC
     */
    public int getSectorCount();

    /**
     * Lecture d'un bloc de la puce Mifare Classic
     *
     * @param block : numéro du bloc à lire
     * @param sector : Numéro du secteur
     * @param key : Clé pour lire les données
     * @param useAsKeyB : Si la clé est la clé B (true) ou la clé A (false)
     * @return valeur du bloc en String
     */
    public String readABlock(int sector, int block, byte[] key, boolean useAsKeyB)throws TagActionException;

    /**
     * Lecture d'un secteur
     *
     * @param sector : Numéro du secteur que l'on souhaite lire
     * @param key : clé permettant l'authentification pour écrire
     * @param useAsKeyB : true si on utilise la keyB false sinon
     * @return data (String de hexadécimale)
     */
    public String readASector(int sector, byte[] key, boolean useAsKeyB)throws TagActionException;

    /**
     * Lecture de toute la puce (Il faut que la clé soit la m^me pour tout les secteurs)
     *
     * @param key : clé permettant l'authentification pour écrire
     * @param useAsKeyB : true si on utilise la keyB false sinon
     * @return data (String de hexadécimale)
     */
    public String readAllSpace(byte[] key, boolean useAsKeyB)throws TagActionException;

    /**
     * Obtenir les informations d'un bloc de la puce NFC
     *
     * @param sector : Numéro du secteur qui contient le bloc dont on veutdes informations
     * @param block : Numéro du bloc dont on veut obtenir les informations
     * @param key : Clé pour accéder aux données
     * @param useAsKeyB : True si on tuilise la KeyB false sinon
     * @return
     */
    public int getInfoForBlock(int sector, int block, byte[] key, boolean useAsKeyB)throws TagActionException;

    /**
     * Obtenir les informations avec les 3 Bits d'Acces
     *
     * @param c1 : bit 1
     * @param c2 : bit 2
     * @param c3 : bit 3
     * @param isSectorTrailer :True si le bloc est un SectorTrailer
     * @return
     *
     *         <ul>
     *         <li>Data Block</li>
     *         <ul>
     *         <li>1 : Read Write Increment Decrement with key A or B</li>
     *         <li>2 : Read with key A or B</li>
     *         <li>3 : Read with key A or B and Write with key B only</li>
     *         <li>4 : Read Write Increment Decrement with B and read + decrement with key A</li>
     *         <li>5 : Read Decrement with key A or B</li>
     *         <li>6 : Read Write with key B</li>
     *         <li>7 : Read with key B</li>
     *         <li>8 : Never</li>
     *         </ul>
     *         <li>Sector Trailer (We can never read Key A)</li>
     *         <ul>
     *         <li>9 : Write KEY A, read acces Bits, read KEY B and write KEY B only with KEY A</li>
     *         <li>10 : Read Acces Bits and Read Key B oncly with KEY A</li>
     *         <li>11 : write KEY A, read Acces Bits and Write KEY B with key B or B AND read Access bits with KEY A</li>
     *         <li>12 : Read Acces bits with KEY A or KEY B</li>
     *         <li>13 : Write KEY A and B, Read/Write Acces bits and read KEY B with "KEY A"</li>
     *         <li>14 : Write KEY A and B, Read/Write Acces bits with "KEY B" and read Acces Bits with "KEY A" too</li>
     *         <li>15 : Read/Write Acces Bits with KEY B and read Acces Bits with KEY A too</li>
     *         <li>16 : Read Acces Bits with KEY A or B</li>
     *         </ul>
     *
     *         <li>-1 : error</li> </ul>
     *
     */
    public int ReadAccesBits(byte c1, byte c2, byte c3, boolean isSectorTrailer);

    /**
     * Création des 4 bytes d'AccessBit pour le sectorTrailer
     *
     * @Explication <ul>
     *              <li>Data Block</li>
     *              <ul>
     *              <li>1 : Read Write Increment Decrement with key A or B</li>
     *              <li>2 : Read with key A or B</li>
     *              <li>3 : Read with key A or B and Write with key B only</li>
     *              <li>4 : Read Write Increment Decrement with B and read + decrement with key A</li>
     *              <li>5 : Read Decrement with key A or B</li>
     *              <li>6 : Read Write with key B</li>
     *              <li>7 : Read with key B</li>
     *              <li>8 : Never</li>
     *              </ul>
     *              <li>Sector Trailer (We can never read Key A)</li>
     *              <ul>
     *              <li>9 : Write KEY A, read acces Bits, read KEY B and write KEY B only with KEY A</li>
     *              <li>10 : Read Acces Bits and Read Key B oncly with KEY A</li>
     *              <li>11 : write KEY A, read Acces Bits and Write KEY B with key B or B AND read Access bits with KEY A</li>
     *              <li>12 : Read Acces bits with KEY A or KEY B</li>
     *              <li>13 : Write KEY A and B, Read/Write Acces bits and read KEY B with "KEY A"</li>
     *              <li>14 : Write KEY A and B, Read/Write Acces bits with "KEY B" and read Acces Bits with "KEY A" too</li>
     *              <li>15 : Read/Write Acces Bits with KEY B and read Acces Bits with KEY A too</li>
     *              <li>16 : Read Acces Bits with KEY A or B</li>
     *              </ul>
     *
     *
     * @param permB0 : permission pour le bloc 0 compris entre 1 et 8
     * @param permB1 : permission pour le bloc 1 compris entre 1 et 8
     * @param permB2 : permission pour le bloc 2 compris entre 1 et 8
     * @param permSectorTrailer : : permission pour le bloc 3 (sector Trailer) compris entre 9 et 16
     * @return 4 bytes d'AccesBit du SectorTrailer
     */
    public byte[] createAccessBit(int permB0, int permB1, int permB2, int permSectorTrailer);

    /**
     * Convertir une chaine hexadécimale en une chaine de caractère
     *
     * @param s : chaine hexadécimale à convertir
     * @return chaine en Ascii
     */
    public String hexToAscii(String s);

    /**
     * Convertir un caractère en décimal
     *
     * @param ch : charactère à convertir
     * @return valeur du caractère en décimal
     */
    public int hexToInt(char ch);

    /**
     * Convertir une chaine de caractère en une chaine hexadécimale
     *
     * @param arg : chaine de charactère
     * @return chaine en hexadécimale
     */
    public String toHex(String arg);


    /**
     * For Activities which want to treat new Intents as Intents with a new Tag attached. If the given Intent has a Tag extra, the Tag and
     * UID will be updated. This method will also check if the device/tag supports Mifare Classic (see return values).
     *
     * @param intent The Intent which should be checked for a new Tag.
     * @return <ul>
     *         <li>1 - The device/tag supports Mifare Classic</li>
     *         <li>0 - The device/tag does not support Mifare Classic</li>
     *         <li>-1 - Wrong Intent (action is not "ACTION_TECH_DISCOVERED").</li>
     *         </ul>
     */
    public int treatAsNewTag(Intent intent);

    /**
     * Convert a string of hex data into a byte array. Original author is: Dave L. (http://stackoverflow.com/a/140861).
     *
     * @param hexString The hex string to convert
     * @return An array of bytes with the values of the string.
     */
    public byte[] hexStringToByteArray(String hexString);
}
