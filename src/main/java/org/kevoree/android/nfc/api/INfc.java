package org.kevoree.android.nfc.api;

import android.content.Context;

public interface INfc {

	// ///////////////////////////////////////////////////////////////

	// Fonctions �critures sur la puce NFC

	// ///////////////////////////////////////////////////////////////
	/**
	 * Ecrire des donn�es sur un block d'un secteur de la puce. (16 bytes)
	 * 
	 * @param sector : dans lequel on veut �crire
	 * @param block : dans lequel on souhaite �crire
	 * @param data : donn�es que l'on souhaite �crire
	 * @param key : cl� permettant l'authentification pour �crire
	 * @param useAsKeyB : true si on utilise la keyB false sinon
	 * @param context
	 * @return true si les donn�es on bien �t� transmise
	 */
	public boolean writeInABlock(int sector, int block, String data, byte[] key, boolean useAsKeyB, Context context);

	/**
	 * Ecrire dans un secteur de la puce NFC MifareClassic On peut �crire 32 bytes dans le secteur 1 (blocs 1 et 2) et 48 bytes dans les autres
	 * secteurs (blocs 0, 1 et 2)
	 * 
	 * @param sector : Secteur dans lequel on souhaite entrer de la data
	 * @param data : information � �crire sur la puce
	 * @param key : Cl� permettant l'authentification au secteur
	 * @param useAsKeyB : Si la cl� utilis� est la cl� A (false) ou la cl� B (true)
	 * @param context
	 * @return true si les donn�es on bien �t� transmise
	 */
	public boolean writeInASector(int sector, String data, byte[] key, boolean useAsKeyB, Context context);

	/**
	 * Ecire dans tout l'espace de la puce NFC (752bytes pour la MifareClassic 1K) Pour cette fonction il faut que tout les secteurs ont la m�me Key
	 * 
	 * @param data : Donn�es � transmettre
	 * @param key : cl� permettant l'authentification pour �crire
	 * @param useAsKeyB : true si on utilise la keyB false sinon
	 * @param context
	 * @return true si les donn�es on bien �t� transmise
	 */
	public boolean writeInAllDataSpace(String data, byte[] key, boolean useAsKeyB, Context context);

	/**
	 * Ecriture de la cl� B en utilisant la cl� A ou la cl� B
	 * 
	 * @param sector : Sector dont on veut changer la cl� B
	 * @param key : Cl� A ou Cl� B actuelle
	 * @param useAsKeyB : True si on utilise la Cl� B false sinon
	 * @param newKeyB : Nouvelle cl� B
	 * @return true si les donn�es ont bien �t� envoy�
	 * @throws ActionNotAllowed : Action non permise
	 * @throws KeyBIsRequired : Cl� B requise
	 * @throws KeyAIsRequired : Cl� A requise
	 * @throws KeyBAndAIsRequired : Cl� A et Cl� B requises
	 */
	public boolean writeKeyB(int sector, byte[] key, boolean useAsKeyB, byte[] newKeyB, Context context) throws ActionNotAllowed, KeyBIsRequired, KeyAIsRequired,
			KeyBAndAIsRequired;

	/**
	 * Ecriture de la Cl� A
	 * 
	 * @param sector : Num�ro du secteur dont on souhaite changer la cl� A
	 * @param key : Cl� avec laquelle on souhaite acc�der au secteurTrailer
	 * @param newKeyA : Nouvelle cl� A
	 * @return : true si l'op�ration d'�criture c'est bien pass�
	 * @throws KeyBIsRequired : La cl� B est requise pour faire cette op�ration
	 * @throws KeyAIsRequired : La cl� A est requise pour faire cette op�ration
	 */
	public boolean writeKeyA(int sector, byte[] key, boolean useAsKeyB, byte[] newKeyA, Context context) throws ActionNotAllowed, KeyBIsRequired, KeyAIsRequired;

	/**
	 * Ecriture de la cl� B en utilisant la cl� A et la cl� B
	 * 
	 * @param sector : Sector dont on veut changer la cl� B
	 * @param keyA : Cl� A actuelle
	 * @param keyB : Cl� B actuelle
	 * @param newKeyB : nouvelle Cl�B
	 * @return true si les donn�es on bien �t� transmise
	 * @throws ActionNotAllowed
	 */
	public boolean writeKeyB(int sector, byte[] keyA, byte[] keyB, byte[] newKeyB, Context context) throws ActionNotAllowed;

	/**
	 * Ecriture des AccesBits du Sector Trailer
	 * 
	 * @param sector : num�ro du secteur dont on souhaite changer les AccessBits
	 * @param keyA : Key A actuelle
	 * @param keyB : Key B actuelle
	 * @param newAccessBit : Nouveau AccesBits du SectorTrailer
	 * @return true si l'�criture c'est bien pass�
	 * @throws ActionNotAllowed : Action non permise
	 */
	public boolean writeAccesBit(int sector, byte[] keyA, byte[] keyB, byte[] newAccessBit, Context context) throws ActionNotAllowed;

	/**
	 * Ecriture des AccesBits du Sector Trailer en utilisant la cl� A ou la cl� B
	 * 
	 * @param sector : num�ro du secteur dont on souhaite changer les AccessBits
	 * @param newAccessBit : Nouveau AccesBits du SectorTrailer
	 * @return true si l'�criture c'est bien pass�
	 * @throws ActionNotAllowed : Action non permise
	 * @throws KeyAIsRequired : Cl� A est requise pour effectuer cette op�ration
	 * @throws KeyBAndAIsRequired : la cl� A et la cl� B sont requise pour effectuer cette op�ration
	 */
	public boolean writeAccesBit(int sector, byte[] key, boolean useAsKeyB, byte[] newAccessBit, Context context) throws ActionNotAllowed, KeyAIsRequired,
			KeyBAndAIsRequired;

	// ///////////////////////////////////////////////////////////////

	// Fonctions lectures sur la puce NFC

	// ///////////////////////////////////////////////////////////////

	/**
	 * Obtenir le Num�ro ID du tag
	 * 
	 * @return ID du TAG (String)
	 */
	public String getId();

	/**
	 * R�cup�re le nombre de bloc dans le TAG NFC
	 * 
	 * @return nombre de secteur de la puce NFC
	 */
	public int getBlockCount();

	/**
	 * R�cup�re le nombre de block dans le secteur en param�tre du tag NFC
	 * 
	 * @param sector : index du secteur dont on souhaite connaitre le nombre de bloc
	 * @return le nombre de bloc dans le secteur demand�
	 */
	public int getBlockCountInSector(int sector);

	/**
	 * R�cup�re le nombre de secteur du tag NFC
	 * 
	 * @return nombre de secteur dans la puce NFC
	 */
	public int getSectorCount();

	/**
	 * Lecture d'un bloc de la puce Mifare Classic
	 * 
	 * @param block : num�ro du bloc � lire
	 * @param sector : Num�ro du secteur
	 * @param key : Cl� pour lire les donn�es
	 * @param useAsKeyB : Si la cl� est la cl� B (true) ou la cl� A (false)
	 * @param context : Context pour retour informations sur l'appli
	 * @return valeur du bloc en String
	 */
	public String readABlock(int sector, int block, byte[] key, boolean useAsKeyB, Context context);

	/**
	 * Lecture d'un secteur
	 * 
	 * @param sector : Num�ro du secteur que l'on souhaite lire
	 * @param key : cl� permettant l'authentification pour �crire
	 * @param useAsKeyB : true si on utilise la keyB false sinon
	 * @param context
	 * @return data (String de hexad�cimale)
	 */
	public String readASector(int sector, byte[] key, boolean useAsKeyB, Context context);

	/**
	 * Lecture de toute la puce (Il faut que la cl� soit la m^me pour tout les secteurs)
	 * 
	 * @param key : cl� permettant l'authentification pour �crire
	 * @param useAsKeyB : true si on utilise la keyB false sinon
	 * @param context
	 * @return data (String de hexad�cimale)
	 */
	public String readAllSpace(byte[] key, boolean useAsKeyB, Context context);

	/**
	 * Obtenir les informations d'un bloc de la puce NFC
	 * 
	 * @param sector : Num�ro du secteur qui contient le bloc dont on veutdes informations
	 * @param block : Num�ro du bloc dont on veut obtenir les informations
	 * @param key : Cl� pour acc�der aux donn�es
	 * @param useAsKeyB : True si on tuilise la KeyB false sinon
	 * @return
	 */
	public int getInfoForBlock(int sector, int block, byte[] key, boolean useAsKeyB);

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
	 * Cr�ation des 4 bytes d'AccessBit pour le sectorTrailer
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
	 * Convertir une chaine hexad�cimale en une chaine de caract�re
	 * 
	 * @param s : chaine hexad�cimale � convertir
	 * @return chaine en Ascii
	 */
	public String hexToAscii(String s);

	/**
	 * Convertir un caract�re en d�cimal
	 * 
	 * @param ch : charact�re � convertir
	 * @return valeur du caract�re en d�cimal
	 */
	public int hexToInt(char ch);

	/**
	 * Convertir une chaine de caract�re en une chaine hexad�cimale
	 * 
	 * @param arg : chaine de charact�re
	 * @return chaine en hexad�cimale
	 */
	public String toHex(String arg);

}
