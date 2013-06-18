package org.kevoree.android.nfc.api;

import java.math.BigInteger;
import java.nio.charset.Charset;

import android.content.Context;
import android.content.Intent;
import android.nfc.TagLostException;

public class NFC_Mifare_classic implements INfc {


    public NFC_Mifare_classic() {

    }

    // /////////////////////////////////////////////////////////////////

    // Fonctions écriture sur la puce NFC

    // /////////////////////////////////////////////////////////////////

    /**
     * Ecrire des données sur un block d'un secteur de la puce. (16 bytes)
     *
     * @param sector : dans lequel on veut écrire
     * @param block : dans lequel on souhaite écrire
     * @param data : données que l'on souhaite écrire en hexadecimale 16bytes (=32 caractères hexadecimaux)
     * @param key : clé permettant l'authentification pour écrire
     * @param useAsKeyB : true si on utilise la keyB false sinon
     * @param context
     * @return true si les données on bien été transmise
     */
    public boolean writeInABlock(int sector, int block, String data, byte[] key, boolean useAsKeyB, Context context) {
        int result = 0;
        MCReader mcReader = Common.checkForTagAndCreateReader(context);
        if (mcReader != null) {

            // Si le secteur ne correspond pas à un secteur de la puce
            if (sector < 0 && sector > mcReader.getSectorCount() - 1) {
                //	System.out.println("le secteur doit etre compris entre 0 et mcReader.getSectorCount()-1 ");
                //	Toast.makeText(context, "le secteur doit etre compris entre 0 et mcReader.getSectorCount()-1", Toast.LENGTH_SHORT).show();
                mcReader.close();
                return false;
            }

            // Si le bloc ne correspond pas à un bloc d'un secteur
            if (block < 0 && block > mcReader.getBlockCount() - 1) {
                //	System.out.println("le bloc doit etre compris entre 0 et mcReader.getBlockCount()-1 ");
                //	Toast.makeText(context, "le bloc doit etre compris entre 0 et mcReader.getBlockCount()-1", Toast.LENGTH_SHORT).show();
                mcReader.close();
                return false;
            }

            // Si la data ne fait pas 32 caractères avec que des caractères
            // hexadécimaux
            if (Common.isHexAnd16Byte(data, context) == false) {
                //	Toast.makeText(context, "La data doit contenir que des caractères hexadécimaux et faire 32 caractères (16 bytes)", Toast.LENGTH_SHORT)
                //			.show();
                mcReader.close();
                return false;
            }

            // Si le bloc choisi correspond à un bloc système
            if (block == 3 || block == 15) {
                //	System.out.println("le bloc correspond à un bloc Système ");
                //	Toast.makeText(context, "le bloc correspond à un bloc Système", Toast.LENGTH_SHORT).show();

                mcReader.close();
                return false;

                // Si le bloc choisi corresponf au bloc id
            } else if (sector == 0 && block == 0) {
                //	System.out.println("le bloc correspond au bloc id");
                //	Toast.makeText(context, "le bloc correspond au bloc id", Toast.LENGTH_SHORT).show();
                mcReader.close();
                return false;
            } else {
                // toutes les vérifications ont bien été faites. On peut écrire
                // sur la puce
                mcReader.close();
                mcReader.connect();
                result = mcReader.writeBlock(sector, block, Common.hexStringToByteArray(data), key, useAsKeyB);
                mcReader.close();
            }

            // Si le résulat est égale à 0 il n'ya pas eu d'erreur
            if (result == 0) {
                //	Toast.makeText(context, "Message transmis à la puce", Toast.LENGTH_SHORT).show();
                mcReader.close();
                return true;
            } else if (result == 4) {
                //	Toast.makeText(context, "Erreur d'authentification", Toast.LENGTH_SHORT).show();
                mcReader.close();
                return false;
            }
        }

        //Toast.makeText(context, "Pas de connection avec le TAG", Toast.LENGTH_SHORT).show();

        return false;
    }

    private boolean writeInBlockTrailer(int sector, int block, String data, byte[] key, boolean useAsKeyB, Context context) {
        int result = 0;
        MCReader mcReader = Common.checkForTagAndCreateReader(context);
        if (mcReader != null) {

            // Si le secteur ne correspond pas à un secteur de la puce
            if (sector < 0 && sector > mcReader.getSectorCount() - 1) {
                //	System.out.println("le secteur doit etre compris entre 0 et mcReader.getSectorCount()-1 ");
                //	Toast.makeText(context, "le secteur doit etre compris entre 0 et mcReader.getSectorCount()-1", Toast.LENGTH_SHORT).show();
                mcReader.close();
                return false;
            }

            // Si le bloc ne correspond pas à un bloc d'un secteur
            if (block != 3 && block != 15) {
                //	System.out.println("le bloc ne correspond pas à un SectorTrailer");
                //	Toast.makeText(context, "le bloc doit etre compris entre 0 et mcReader.getBlockCount()-1", Toast.LENGTH_SHORT).show();
                mcReader.close();
                return false;
            }

            // Si la data ne fait pas 32 caractères avec que des caractères
            // hexadécimaux
            if (Common.isHexAnd16Byte(data, context) == false) {
                //	Toast.makeText(context, "La data doit contenir que des caractères hexadécimaux et faire 32 caractères (16 bytes)", Toast.LENGTH_SHORT)
                //			.show();
                mcReader.close();
                return false;
            }

            // toutes les vérifications ont bien été faites. On peut écrire
            // sur la puce
            mcReader.close();
            mcReader.connect();
            result = mcReader.writeBlock(sector, block, Common.hexStringToByteArray(data), key, useAsKeyB);
            mcReader.close();

            // Si le résulat est égale à 0 il n'ya pas eu d'erreur
            if (result == 0) {
                //	Toast.makeText(context, "Message transmis à la puce", Toast.LENGTH_SHORT).show();
                mcReader.close();
                return true;
            } else if (result == 4) {
                //	Toast.makeText(context, "Erreur d'authentification", Toast.LENGTH_SHORT).show();
                mcReader.close();
                return false;
            } else if (result == 3) {
                //	Toast.makeText(context, "Erreur 3", Toast.LENGTH_SHORT).show();
                mcReader.close();
                return false;
            } else if (result == 2) {
                //	Toast.makeText(context, "Erreur 2", Toast.LENGTH_SHORT).show();
                mcReader.close();
                return false;
            } else if (result == 1) {
                //	Toast.makeText(context, "Erreur 1", Toast.LENGTH_SHORT).show();
                mcReader.close();
                return false;
            } else if (result == -1) {
                //	Toast.makeText(context, "Erreur -1", Toast.LENGTH_SHORT).show();
                mcReader.close();
                return false;
            }
        }

        //Toast.makeText(context, "Pas de connection avec le TAG", Toast.LENGTH_SHORT).show();

        return false;
    }

    /**
     * Ecrire dans un secteur de la puce NFC MifareClassic On peut écrire 32 bytes dans le secteur 1 (blocs 1 et 2) et 48 bytes dans les autres
     * secteurs (blocs 0, 1 et 2)
     *
     * @param sector : Secteur dans lequel on souhaite entrer de la data
     * @param data : information à écrire sur la puce (String d'hexadécimaux)
     * @param key : Clé permettant l'authentification au secteur
     * @param useAsKeyB : Si la clé utilisé est la clé A (false) ou la clé B (true)
     * @param context
     * @return true si les données on bien été transmise
     */
    public boolean writeInASector(int sector, String data, byte[] key, boolean useAsKeyB, Context context) {
        int result = -1;

        // On récupère MCReader
        MCReader mcReader = Common.checkForTagAndCreateReader(context);

        if (mcReader != null) {
            // Le secteur doit etre compris entre 0 et le nombre de secteur-1
            if (sector < 0 && sector > mcReader.getSectorCount() - 1) {
                //	System.out.println("le secteur doit etre compris entre 0 et mcReader.getSectorCount()-1 ");
                mcReader.close();
                return false;
            }

            // Si le secteur 0 est sélectionné on peut écrire que 32 bytes (
            // bloc 2
            // et 3)
            if (sector == 0) {
                if (Common.isHexAnd32Byte(data, context) == false) {
                    mcReader.close();
                    //		System.out.println("SECTOR 0 :: 32 BYTES");
                    return false;
                }

            } else if (Common.isHexAnd48Byte(data, context) == false) {
                // autres secteurs, 48 bytes
                //	System.out.println("SECTOR 0 :: 48 BYTES");
                mcReader.close();
                return false;
            }

            int i = 0;

            if (sector == 0) {
                for (int j = 1; j < 3; j++) {
                    mcReader.close();
                    mcReader.connect();
                    String string = (data.subSequence(i, i + 32).toString());
                    //	System.out.println(string);
                    result = mcReader.writeBlock(sector, j, Common.hexStringToByteArray(string), key, useAsKeyB);
                    mcReader.close();
                    if (result != 0) {
                        return false;
                    }
                    i = i + 32;
                }

            } else {

                for (int j = 0; j < 3; j++) {
                    mcReader.close();
                    mcReader.connect();
                    String string = (data.subSequence(i, i + 32).toString());
                    //	System.out.println(string);
                    result = mcReader.writeBlock(sector, j, Common.hexStringToByteArray(string), key, useAsKeyB);
                    mcReader.close();
                    if (result != 0) {
                        return false;
                    }
                    i = i + 32;
                }
            }

            if (result == 0) {
                //	System.out.println("TRUE");
                //Toast.makeText(context, "Transmission Effectué", Toast.LENGTH_SHORT).show();
                return true;
            }
        }
        // System.out.println("FALSE");
        //Toast.makeText(context, "Pas de connection", Toast.LENGTH_SHORT).show();
        return false;

    }

    /**
     * Ecire dans tout l'espace de la puce NFC (752bytes pour la MifareClassic 1K) Pour cette fonction il faut que tout les secteurs ont la même Key
     *
     * @param data : Données à transmettre (String d'hexadécimaux)
     * @param key : clé permettant l'authentification pour écrire
     * @param useAsKeyB : true si on utilise la keyB false sinon
     * @param context
     * @return true si les données on bien été transmise
     */
    public boolean writeInAllDataSpace(String data, byte[] key, boolean useAsKeyB, Context context) {
        int result = 0;

        MCReader mcReader = Common.checkForTagAndCreateReader(context);

        // mcReader.getSize();
        if (mcReader != null) {

            int count = 1;
            while (data.length() > (16 * count)) {
                count++;
            }
            //System.out.println("nombre de block : " + count);

            if (data.length() < 1504) {
                while (data.length() != 1504) {
                    data = data + "0";
                }
            }

            if (!(Common.isHexAnd752Byte(data, context))) {
                mcReader.close();
                //Toast.makeText(context, "Données éronnées", Toast.LENGTH_SHORT).show();
                return false;

            }
            int k = 0;
            // parcours de tous les secteurs
            for (int j = 0; j < mcReader.getSectorCount(); j++) {

                if (j == 0) {
                    // parcours secteur 0
                    for (int i = 1; i < mcReader.getBlockCountInSector(j) - 1; i++) {
                        mcReader.close();
                        mcReader.connect();
                        String string = (data.subSequence(k, k + 32).toString());
                        //	System.out.println("s : " + j + "b : " + i + " data : " + string);
                        result = mcReader.writeBlock(j, i, Common.hexStringToByteArray(string), key, useAsKeyB);
                        mcReader.close();
                        if (result != 0) {
                            //Toast.makeText(context, "Error Sector : " + j + " Block : " + i, Toast.LENGTH_SHORT).show();
                            return false;
                        }
                        k = k + 32;
                    }

                } else {
                    // parcours autres secteurs
                    for (int i = 0; i < mcReader.getBlockCountInSector(j) - 1; i++) {
                        mcReader.close();
                        mcReader.connect();
                        String string = (data.subSequence(k, k + 32).toString());
                        //	System.out.println("s : " + j + "b : " + i + " data : " + string);
                        result = mcReader.writeBlock(j, i, Common.hexStringToByteArray(string), key, useAsKeyB);
                        mcReader.close();
                        if (result != 0) {
                            //	Toast.makeText(context, "Error Sector : " + j + " Block : " + i, Toast.LENGTH_SHORT).show();
                            return false;
                        }
                        k = k + 32;
                    }
                }
            }

            if (result == 0) {
                //	System.out.println("TRUE");
                //Toast.makeText(context, "Données transmises  ", Toast.LENGTH_SHORT).show();
                return true;
            }
        }
        //Toast.makeText(context, "Pas de connection", Toast.LENGTH_SHORT).show();
        return false;

    }

    /**
     * Ecire dans tout l'espace de la puce NFC (752bytes pour la MifareClassic 1K) Pour cette fonction il faut que tout les secteurs ont la même Key
     *
     * @param data : Données à transmettre (String d'hexadécimaux)
     * @param key : clé permettant l'authentification pour écrire
     * @param useAsKeyB : true si on utilise la keyB false sinon
     * @param context
     * @return true si les données on bien été transmise
     */
    public boolean writeInAllDataSpaceWithAllKey(String data, byte[][] key, boolean useAsKeyB, Context context) {
        int result = 0;

        MCReader mcReader = Common.checkForTagAndCreateReader(context);

        // mcReader.getSize();
        if (mcReader != null) {

            int count = 1;
            while (data.length() > (16 * count)) {
                count++;
            }
            //	System.out.println("nombre de block : " + count);

            if (data.length() < 1504) {
                while (data.length() != 1504) {
                    data = data + "0";
                }
            }

            if (!(Common.isHexAnd752Byte(data, context))) {
                mcReader.close();
                //Toast.makeText(context, "Données éronnées", Toast.LENGTH_SHORT).show();
                return false;

            }
            int k = 0;
            // parcours de tous les secteurs
            for (int j = 0; j < mcReader.getSectorCount(); j++) {

                if (j == 0) {
                    // parcours secteur 0
                    for (int i = 1; i < mcReader.getBlockCountInSector(j) - 1; i++) {
                        mcReader.close();
                        mcReader.connect();
                        String string = (data.subSequence(k, k + 32).toString());
                        //	System.out.println("s : " + j + "b : " + i + " data : " + string);
                        result = mcReader.writeBlock(j, i, Common.hexStringToByteArray(string), key[j], useAsKeyB);
                        mcReader.close();
                        if (result != 0) {
                            //	Toast.makeText(context, "Error Sector : " + j + " Block : " + i, Toast.LENGTH_SHORT).show();
                            return false;
                        }
                        k = k + 32;
                    }

                } else {
                    // parcours autres secteurs
                    for (int i = 0; i < mcReader.getBlockCountInSector(j) - 1; i++) {
                        mcReader.close();
                        mcReader.connect();
                        String string = (data.subSequence(k, k + 32).toString());
                        //	System.out.println("s : " + j + "b : " + i + " data : " + string);
                        result = mcReader.writeBlock(j, i, Common.hexStringToByteArray(string), key[j], useAsKeyB);
                        mcReader.close();
                        if (result != 0) {
                            //	Toast.makeText(context, "Error Sector : " + j + " Block : " + i, Toast.LENGTH_SHORT).show();
                            return false;
                        }
                        k = k + 32;
                    }
                }
            }

            if (result == 0) {
                //	System.out.println("TRUE");
                //	Toast.makeText(context, "Données transmises  ", Toast.LENGTH_SHORT).show();
                return true;
            }
        }
        //Toast.makeText(context, "Pas de connection", Toast.LENGTH_SHORT).show();
        return false;

    }

    /**
     * Ecriture des AccesBits du Sector Trailer en utilisant la clé A et la clé B
     *
     * @param sector : numéro du secteur dont on souhaite changer les AccessBits
     * @param keyA : Key A actuelle
     * @param keyB : Key B actuelle
     * @param newAccessBit : Nouveau AccesBits du SectorTrailer
     * @return true si l'écriture c'est bien passé
     * @throws ActionNotAllowed : Action non permise
     */
    public boolean writeAccesBit(int sector, byte[] keyA, byte[] keyB, byte[] newAccessBit, Context context) throws ActionNotAllowed {

        // récupération du Secteur Trailer du secteur voulu
        String result = this.readABlock(sector, 3, keyA, false, context);

        if (result != null) {
            // Récupération des paramètres pour le secteur
            byte[] ac = Common.hexStringToByteArray(result.subSequence(12, 20).toString());
            byte[][] AC = Common.acToACMatrix(ac);

            // Lecture des permissions sur le sector Trailer
            int permission = this.ReadAccesBits(AC[0][3], AC[1][3], AC[2][3], true);

            // Vérification des permissions afin de connaitre si on peut effectuer cette action
            if (!(permission == 13 || permission == 14 || permission == 15)) {
                throw new ActionNotAllowed("We can't write AccesBits with this parameters");
            }
            if (permission == 13) {
                String bloc = Common.byte2HexString(keyA) + Common.byte2HexString(newAccessBit) + result.substring(20, 32);
                //	System.out.println("nouveau sector Trailer ::: " + bloc);
                // : Write with KEY A
                return this.writeInBlockTrailer(sector, 3, bloc, keyA, false, context);
            } else if (permission == 14 || permission == 15) {
                // : Write with KEY B
                String bloc = Common.byte2HexString(keyA) + Common.byte2HexString(newAccessBit) + Common.byte2HexString(keyB);
                //	System.out.println("nouveau sector Trailer ::: " + bloc);
                return this.writeInBlockTrailer(sector, 3, bloc, keyB, true, context);
            }

        }
        //Toast.makeText(context, "Pas de connection", Toast.LENGTH_SHORT).show();
        return false;
    }




    /**
     * Ecriture de la clé A en utilisant la clé A et la clé B
     *
     * @param sector : Sector dont on veut changer la clé A
     * @param keyA : Clé A actuelle
     * @param keyB : Clé B actuelle
     * @param newKeyA : nouvelle Clé A
     * @return true si les données on bien été transmise
     * @throws ActionNotAllowed
     */
    public boolean writeKeyA(int sector, byte[] keyA, byte[] keyB, byte[] newKeyA, Context context) throws ActionNotAllowed {

        // récupération du Secteur Trailer du secteur voulu
        String result = this.readABlock(sector, 3, keyA, false, context);

        if (result != null) {
            // Récupération des paramètres pour le secteur
            byte[] ac = Common.hexStringToByteArray(result.subSequence(12, 20).toString());
            byte[][] AC = Common.acToACMatrix(ac);

            // Lecture des permissions sur le sector Trailer
            int permission = this.ReadAccesBits(AC[0][3], AC[1][3], AC[2][3], true);

            // Vérification des permissions afin de connaitre si on peut effectuer cette action
            if (!(permission == 9 || permission == 11 || permission == 13 || permission == 14)) {
                throw new ActionNotAllowed("We can't write KEYA with this parameters");
            }

            // Si Permission = 9 ou 13 alors on peut écrire la nouvelle clé B
            if (permission == 9 || permission == 13) {
                String bloc = Common.byte2HexString(newKeyA) + result.subSequence(12, 32);
                //	System.out.println("Nouveau Bloc ::: " + bloc);
                //	System.out.println("Ancien  Bloc ::: " + result);
                // : key A
                return this.writeInBlockTrailer(sector, 3, bloc, keyA, false, context);
            } else if (permission == 11 || permission == 14) {
                String bloc = Common.byte2HexString(newKeyA) + result.subSequence(12, 20) + Common.byte2HexString(keyB);
                //	System.out.println("Nouveau Bloc 2 ::: " + bloc);
                //	System.out.println("Ancien  Bloc 2 ::: " + result);
                // : key b
                return this.writeInBlockTrailer(sector, 3, bloc, keyB, true, context);
            }
        }
        return false;
    }


    /**
     * Ecriture de la clé B en utilisant la clé A et la clé B
     *
     * @param sector : Sector dont on veut changer la clé B
     * @param keyA : Clé A actuelle
     * @param keyB : Clé B actuelle
     * @param newKeyB : nouvelle CléB
     * @return true si les données on bien été transmise
     * @throws ActionNotAllowed
     */
    public boolean writeKeyB(int sector, byte[] keyA, byte[] keyB, byte[] newKeyB, Context context) throws ActionNotAllowed {

        String result = this.readABlock(sector, 3, keyA, false, context);

        if (result != null) {

            byte[] ac = Common.hexStringToByteArray(result.subSequence(12, 20).toString());

            byte[][] AC = Common.acToACMatrix(ac);
            int permission = this.ReadAccesBits(AC[0][3], AC[1][3], AC[2][3], true);

            if (!(permission == 9 || permission == 11 || permission == 13 || permission == 14)) {
                throw new ActionNotAllowed("We can't write KEYA with this parameters");
            }

            if (permission == 9 || permission == 13) {
                String bloc = Common.byte2HexString(keyA) + result.subSequence(12, 20) + Common.byte2HexString(newKeyB);
                //	System.out.println(permission + "Nouveau Bloc ::: " + bloc);
                //	System.out.println("Ancien  Bloc ::: " + result);
                // ecrire avec clé A
                this.writeInBlockTrailer(sector, 3, bloc, keyA, false, context);
                return true;
            } else if (permission == 11 || permission == 14) {
                String bloc = Common.byte2HexString(keyA) + result.subSequence(12, 20) + Common.byte2HexString(newKeyB);
                //	System.out.println(permission + "Nouveau Bloc ::: " + bloc);
                //	System.out.println("Ancien  Bloc ::: " + result);
                // ecrire avec clé B
                this.writeInBlockTrailer(sector, 3, bloc, keyB, true, context);
                return true;
            }

        }
        return false;
    }

    // ////////////////////////////////////////////////////////////

    // Fonctions lectures de la puce

    // ////////////////////////////////////////////////////////////

    /**
     * Obtenir le Numéro ID du tag
     *
     * @return ID du TAG (String)
     */
    public String getId() {
        MCReader mcReader = Common.checkForTagAndCreateReader(null);
        if (mcReader != null) {
            mcReader.close();
            return Common.byte2HexString(Common.getUID());
        }
        return "No ID discovered !";
    }

    /**
     * Lecture d'un bloc de la puce Mifare Classic
     *
     * @param block : numéro du bloc à lire
     * @param sector : Numéro du secteur
     * @param key : Clé pour lire les données
     * @param useAsKeyB : Si la clé est la clé B (true) ou la clé A (false)
     * @param context : Context pour retour informations sur l'appli
     * @return valeur du bloc en String
     */
    public String readABlock(int sector, int block, byte[] key, boolean useAsKeyB, Context context) {

        MCReader mcReader = Common.checkForTagAndCreateReader(context);

        String[] string2 = null;
        // * Lecture du bloc
        if (mcReader != null) {
            if (sector<0 || sector>mcReader.getBlockCount()-1){
                mcReader.close();
                return null;
            }
            try {
                string2 = mcReader.readSector(sector, key, useAsKeyB);

            } catch (TagLostException e) {
                e.printStackTrace();
            }
            if (string2 != null && block >= 0 && block < mcReader.getBlockCountInSector(sector)) {
                mcReader.close();
                return string2[block];
            }
            mcReader.close();
        }
        // Toast.makeText(context, "Pas de connection avec le TAG", Toast.LENGTH_SHORT).show();
        return null;
    }

    /**
     * Lecture d'un secteur
     *
     * @param sector : Numéro du secteur que l'on souhaite lire
     * @param key : clé permettant l'authentification pour écrire
     * @param useAsKeyB : true si on utilise la keyB false sinon
     * @param context
     * @return data (String de hexadécimale)
     */
    public String readASector(int sector, byte[] key, boolean useAsKeyB, Context context) {

        // se connecter à la puce NFC
        MCReader mcReader = Common.checkForTagAndCreateReader(context);

        if (mcReader != null) {
            // * Lecture bloc par bloc de la puce NFC avec clé par défaut
            if (sector<0 || sector>mcReader.getBlockCount()-1){
                mcReader.close();
                return null;
            }
            String[] dataPuce = null;

            try {
                dataPuce = mcReader.readSector(sector, key, useAsKeyB);
            } catch (TagLostException e) {
                e.printStackTrace();
            }

            String data = "";
            if (dataPuce != null) {

                for (int j = 0; j < mcReader.getBlockCountInSector(sector); j++) {
                    //	System.out.println(j);
                    data += dataPuce[j]; // + " \0A"
                }

                mcReader.close();

                //	System.out.println(data);
                return data;
            }
            mcReader.close();
        }
        //	Toast.makeText(context, "Pas de connection", Toast.LENGTH_SHORT).show();
        return null;
    }

    /**
     * Lecture de toute la puce
     *
     * @param key
     * @param useAsKeyB
     * @param context
     * @return
     */
    public String readAllSpace(byte[] key, boolean useAsKeyB, Context context) {
        // se connecter à la puce NFC
        MCReader mcReader = Common.checkForTagAndCreateReader(context);

        // * Lecture bloc par bloc de la puce NFC avec clé par défaut

        String[][] string = new String[100][4];

        String[] string2 = null;
        if (mcReader != null) {

            for (int i = 0; i < mcReader.getSectorCount(); i++) {
                try {
                    string2 = mcReader.readSector(i, key, false);
                } catch (TagLostException e) {
                    e.printStackTrace();
                }
                if (string2 != null) {
                    string[i][0] = string2[0];
                    string[i][1] = string2[1];
                    string[i][2] = string2[2];
                    string[i][3] = string2[3];
                } else {
                    mcReader.close();
                    return null;// "Erreur Authentification secteur :" + i;
                }
            }

            String data = "";

            for (int i = 0; i < mcReader.getSectorCount(); i++) {

                for (int j = 0; j < mcReader.getBlockCountInSector(i); j++) {
                    data += string[i][j];// + "0A";
                }
                // data += "0A";

            }

            mcReader.close();

            //	System.out.println(data);
            return data;
        }
        //Toast.makeText(context, "Pas de connection", Toast.LENGTH_SHORT).show();
        return null;

    }

    /**
     * Récupère le nombre de bloc dans le TAG NFC
     *
     * @return nombre de secteur de la puce NFC
     */
    public int getBlockCount() {
        MCReader mcReader = Common.checkForTagAndCreateReader(null);
        if (mcReader != null) {
            int x = mcReader.getBlockCount();
            mcReader.close();
            return x;
        }
        return -1;
    }

    /**
     * Récupère le nombre de secteur du tag NFC
     *
     * @return nombre de secteur dans la puce NFC
     */
    public int getSectorCount() {
        MCReader mcReader = Common.checkForTagAndCreateReader(null);
        if (mcReader != null) {
            int x = mcReader.getSectorCount();
            mcReader.close();
            return x;
        }
        return -1;
    }

    /**
     * Récupère le nombre de block dans le secteur en paramètre du tag NFC
     *
     * @param sector : index du secteur dont on souhaite connaitre le nombre de bloc
     * @return le nombre de bloc dans le secteur demandé
     */
    public int getBlockCountInSector(int sector) {
        MCReader mcReader = Common.checkForTagAndCreateReader(null);
        if (mcReader != null) {
            int x = mcReader.getBlockCountInSector(sector);
            mcReader.close();
            return x;
        }
        return -1;
    }

    /**
     * Obtenir les informations d'un bloc de la puce NFC
     *
     * @param sector : Numéro du secteur qui contient le bloc dont on veutdes informations
     * @param block : Numéro du bloc dont on veut obtenir les informations
     * @param key : Clé pour accéder aux données
     * @param useAsKeyB : True si on tuilise la KeyB false sinon
     * @return <ul>
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
     */
    public int getInfoForBlock(int sector, int block, byte[] key, boolean useAsKeyB) {

        // Lecture du sector Trailer du Secteur demandé
        String result = this.readABlock(sector, 3, key, useAsKeyB, null);

        if (result != null) {
            // Récupération des paramètres pour le secteur
            byte[] ac = Common.hexStringToByteArray(result.subSequence(12, 20).toString());
            byte[][] AC = Common.acToACMatrix(ac);

            boolean trailer;
            if (block != 3) {
                trailer = false;
            } else {
                trailer = true;
            }
            // lecture des permissions pour le block demandé
            int permission = this.ReadAccesBits(AC[0][block], AC[1][block], AC[2][block], trailer);
            return permission;
        }
        return -1;
    }

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
    public int ReadAccesBits(byte c1, byte c2, byte c3, boolean isSectorTrailer) {
        if (isSectorTrailer == false) {
            if (c1 == 0) {
                if (c2 == 0) {
                    if (c3 == 0) {
                        // 000
                        return 1;
                    } else {
                        // 001
                        return 5;
                    }
                } else {
                    if (c3 == 0) {
                        // 010
                        return 2;
                    } else {
                        // 011
                        return 6;
                    }
                }
            } else {
                if (c2 == 0) {
                    if (c3 == 0) {
                        // 100
                        return 3;
                    } else {
                        // 101
                        return 7;
                    }
                } else {
                    if (c3 == 0) {
                        // 110
                        return 4;
                    } else {
                        // 111
                        return 8;
                    }
                }
            }
        } else {
            if (c1 == 0) {
                if (c2 == 0) {
                    if (c3 == 0) {
                        // 000
                        return 9;
                    } else {
                        // 001
                        return 13;
                    }
                } else {
                    if (c3 == 0) {
                        // 010
                        return 10;
                    } else {
                        // 011
                        return 14;
                    }
                }
            } else {
                if (c2 == 0) {
                    if (c3 == 0) {
                        // 100
                        return 11;
                    } else {
                        // 101
                        return 15;
                    }
                } else {
                    if (c3 == 0) {
                        // 110
                        return 12;
                    } else {
                        // 111
                        return 16;
                    }
                }
            }
        }

    }

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
    public byte[] createAccessBit(int permB0, int permB1, int permB2, int permSectorTrailer) {

        String[] block0 = getAccesbit(permB0);
        String[] block1 = getAccesbit(permB1);
        String[] block2 = getAccesbit(permB2);
        String[] block3 = getAccesbit(permSectorTrailer);

        String accessBit = binaryToHexa(not(block3[1]) + not(block2[1]) + not(block1[1]) + not(block0[1]))
                + binaryToHexa(not(block3[0]) + not(block2[0]) + not(block1[0]) + not(block0[0]))
                + binaryToHexa(block3[0] + block2[0] + block1[0] + block0[0])
                + binaryToHexa(not(block3[2]) + not(block2[2]) + not(block1[2]) + not(block0[2]))
                + binaryToHexa(block3[2] + block2[2] + block1[2] + block0[2]) + binaryToHexa(block3[1] + block2[1] + block1[1] + block0[1]) + "69";
        //TODO : dernier byte Access Bit ???

        return Common.hexStringToByteArray(accessBit);

    }

    /**
     * Récupère les 3 bits d'AccessBit pour une permission
     *
     * @param permission
     * @return tableau de string de trois bits
     */
    private String[] getAccesbit(int permission) {
        String[] retour = new String[3];

        if (permission == 1 || permission == 9) {
            retour[0] = "0";
            retour[1] = "0";
            retour[2] = "0";

            return retour;

        } else if (permission == 2 || permission == 10) {
            retour[0] = "0";
            retour[1] = "1";
            retour[2] = "0";

            return retour;

        } else if (permission == 3 || permission == 11) {
            retour[0] = "1";
            retour[1] = "0";
            retour[2] = "0";

            return retour;

        } else if (permission == 4 || permission == 12) {
            retour[0] = "1";
            retour[1] = "1";
            retour[2] = "0";

            return retour;

        } else if (permission == 5 || permission == 13) {
            retour[0] = "0";
            retour[1] = "0";
            retour[2] = "1";

            return retour;

        } else if (permission == 6 || permission == 14) {
            retour[0] = "0";
            retour[1] = "1";
            retour[2] = "1";

            return retour;

        } else if (permission == 7 || permission == 15) {
            retour[0] = "1";
            retour[1] = "0";
            retour[2] = "1";

            return retour;

        } else {
            retour[0] = "1";
            retour[1] = "1";
            retour[2] = "1";

            return retour;
        }

    }

    // ////////////////////////////////////////////////////////////

    // Fonctions Annexes

    // ////////////////////////////////////////////////////////////

    /**
     * Convertir une chaine hexadécimale en une chaine de caractère
     *
     * @param s : chaine hexadécimale à convertir
     * @return chaine en Ascii
     */
    public String hexToAscii(String s) {
        int n = s.length();
        StringBuilder sb = new StringBuilder(n / 2);
        for (int i = 0; i < n; i += 2) {
            char a = s.charAt(i);
            char b = s.charAt(i + 1);
            if (a != 0 && b != 0) {
                sb.append((char) ((hexToInt(a) << 4) | hexToInt(b)));
            }
        }
        return sb.toString();
    }

    /**
     * Convertir un caractère en décimal
     *
     * @param ch : charactère à convertir
     * @return valeur du caractère en décimal
     */
    public int hexToInt(char ch) {
        if ('a' <= ch && ch <= 'f') {
            return ch - 'a' + 10;
        }
        if ('A' <= ch && ch <= 'F') {
            return ch - 'A' + 10;
        }
        if ('0' <= ch && ch <= '9') {
            return ch - '0';
        }
        return 0;
    }

    /**
     * Convertir une chaine de caractère en une chaine hexadécimale
     *
     * @param arg : chaine de charactère
     * @return chaine en hexadécimale
     */
    public String toHex(String arg) {
        return String.format("%x", new BigInteger(1, arg.getBytes(Charset.defaultCharset())));
    }

    /**
     * Convert une chaine binaire de 4 bits en un hexadécimal
     *
     * @param binary Chaine de 4 bits
     *
     * @return hexadécimale
     */
    private String binaryToHexa(String binary) {
        int value = Character.getNumericValue(binary.charAt(0)) * 8 + Character.getNumericValue(binary.charAt(1)) * 4
                + Character.getNumericValue(binary.charAt(2)) * 2 + Character.getNumericValue(binary.charAt(3)) * 1;
        return Integer.toHexString(value);

    }

    /**
     * NOT : Inversion du bits (if bit = 0 on retourne 1 ...)
     *
     * @param x : String contenant le bit
     * @return : on retourne not(x)
     */
    private String not(String x) {
        if (x.equals("0")) {
            return "1";
        } else {
            return "0";
        }
    }


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
    public int treatAsNewTag(Intent intent){
        return Common.treatAsNewTag(intent, null);

    }

    /**
     * Convert a string of hex data into a byte array. Original author is: Dave L. (http://stackoverflow.com/a/140861).
     *
     * @param hexString The hex string to convert
     * @return An array of bytes with the values of the string.
     */
    public byte[] hexStringToByteArray(String hexString){
        return Common.hexStringToByteArray(hexString);
    }

    /**
     * Obtenir info sur AccessBits
     * @param i : index of acces bit
     * @return correspondance
     */
    public String GetStringInfo(int i) {
        switch (i) {
            case 1:
                return "Read Write Increment Decrement with key A or B";
            case 2:
                return "Read with key A or B";
            case 3:
                return "Read with key A or B and Write with key B only";
            case 4:
                return "Read Write Increment Decrement with B and read + decrement with key A";
            case 5:
                return "Read Decrement with key A or B";
            case 6:
                return "Read Write with key B";
            case 7:
                return "Read with key B";
            case 8:
                return "Nothing";
            case 9:
                return "Write KEY A, read acces Bits, read KEY B and write KEY B only with KEY A";
            case 10:
                return "Read Acces Bits and Read Key B oncly with KEY A";
            case 11:
                return "Write KEY A, read Acces Bits and Write KEY B with key B or B AND read Access bits with KEY A";
            case 12:
                return "Read Acces bits with KEY A or KEY B";
            case 13:
                return "Write KEY A and B, Read/Write Acces bits and read KEY B with KEY A";
            case 14:
                return "Write KEY A and B, Read/Write Acces bits with KEY B and read Acces Bits with KEY A too";
            case 15:
                return "Read/Write Acces Bits with KEY B and read Acces Bits with KEY A too";
            case 16:
                return "Read Acces Bits with KEY A or B";
            default:
                return "";
        }

    }

}
