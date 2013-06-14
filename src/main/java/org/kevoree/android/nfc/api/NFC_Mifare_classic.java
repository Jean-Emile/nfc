package org.kevoree.android.nfc.api;

import java.math.BigInteger;
import java.nio.charset.Charset;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.nfc.TagLostException;
import android.nfc.tech.MifareClassic;
import android.widget.Toast;

public class NFC_Mifare_classic implements INfc {

	boolean writeInSectorTrailer;

	public NFC_Mifare_classic() {

	}

	// /////////////////////////////////////////////////////////////////

	// Fonctions �criture sur la puce NFC

	// /////////////////////////////////////////////////////////////////

	/**
	 * Ecrire des donn�es sur un block d'un secteur de la puce. (16 bytes)
	 * 
	 * @param sector : dans lequel on veut �crire
	 * @param block : dans lequel on souhaite �crire
	 * @param data : donn�es que l'on souhaite �crire en hexadecimale 16bytes (=32 caract�res hexadecimaux)
	 * @param key : cl� permettant l'authentification pour �crire
	 * @param useAsKeyB : true si on utilise la keyB false sinon
	 * @param context
	 * @return true si les donn�es on bien �t� transmise
	 */
	public boolean writeInABlock(int sector, int block, String data, byte[] key, boolean useAsKeyB, Context context) {
		int result = 0;
		MCReader mcReader = Common.checkForTagAndCreateReader(context);
		if (mcReader != null) {

			// Si le secteur ne correspond pas � un secteur de la puce
			if (sector < 0 && sector > mcReader.getSectorCount() - 1) {
				System.out.println("le secteur doit etre compris entre 0 et mcReader.getSectorCount()-1 ");
				Toast.makeText(context, "le secteur doit etre compris entre 0 et mcReader.getSectorCount()-1", Toast.LENGTH_SHORT).show();
				mcReader.close();
				return false;
			}

			// Si le bloc ne correspond pas � un bloc d'un secteur
			if (block < 0 && block > mcReader.getBlockCount() - 1) {
				System.out.println("le bloc doit etre compris entre 0 et mcReader.getBlockCount()-1 ");
				Toast.makeText(context, "le bloc doit etre compris entre 0 et mcReader.getBlockCount()-1", Toast.LENGTH_SHORT).show();
				mcReader.close();
				return false;
			}

			// Si la data ne fait pas 32 caract�res avec que des caract�res
			// hexad�cimaux
			if (Common.isHexAnd16Byte(data, context) == false) {
				Toast.makeText(context, "La data doit contenir que des caract�res hexad�cimaux et faire 32 caract�res (16 bytes)", Toast.LENGTH_SHORT)
						.show();
				mcReader.close();
				return false;
			}

			// Si le bloc choisi correspond � un bloc syst�me
			if (block == 3 || block == 15) {
				System.out.println("le bloc correspond � un bloc Syst�me ");
				Toast.makeText(context, "le bloc correspond � un bloc Syst�me", Toast.LENGTH_SHORT).show();
				
				mcReader.close();
				return false;
			

				// Si le bloc choisi corresponf au bloc id
			} else if (sector == 0 && block == 0) {
				System.out.println("le bloc correspond au bloc id");
				Toast.makeText(context, "le bloc correspond au bloc id", Toast.LENGTH_SHORT).show();
				mcReader.close();
				return false;
			} else {
				// toutes les v�rifications ont bien �t� faites. On peut �crire
				// sur la puce
				mcReader.close();
				mcReader.connect();
				result = mcReader.writeBlock(sector, block, Common.hexStringToByteArray(data), key, useAsKeyB);
				mcReader.close();
			}

			// Si le r�sulat est �gale � 0 il n'ya pas eu d'erreur
			if (result == 0) {
				Toast.makeText(context, "Message transmis � la puce", Toast.LENGTH_SHORT).show();
				mcReader.close();
				return true;
			} else if (result == 4) {
				Toast.makeText(context, "Erreur d'authentification", Toast.LENGTH_SHORT).show();
				mcReader.close();
				return false;
			}
		}

		Toast.makeText(context, "Pas de connection avec le TAG", Toast.LENGTH_SHORT).show();

		return false;
	}

	@SuppressWarnings("unused")
	private int writeInBlockTrailer (MCReader mcReader, int sector, int block, String data, byte[] key, boolean useAsKeyB) {
		System.out.println("I know What i'm !!!");
		mcReader.close();
		mcReader.connect();
		int result = mcReader.writeBlock(sector, block, Common.hexStringToByteArray(data), key, useAsKeyB);
		mcReader.close();
		return result;
	}
	/**
	 * Ecrire dans un secteur de la puce NFC MifareClassic On peut �crire 32 bytes dans le secteur 1 (blocs 1 et 2) et 48 bytes dans les autres
	 * secteurs (blocs 0, 1 et 2)
	 * 
	 * @param sector : Secteur dans lequel on souhaite entrer de la data
	 * @param data : information � �crire sur la puce (String d'hexad�cimaux)
	 * @param key : Cl� permettant l'authentification au secteur
	 * @param useAsKeyB : Si la cl� utilis� est la cl� A (false) ou la cl� B (true)
	 * @param context
	 * @return true si les donn�es on bien �t� transmise
	 */
	public boolean writeInASector(int sector, String data, byte[] key, boolean useAsKeyB, Context context) {
		int result = -1;

		// On r�cup�re MCReader
		MCReader mcReader = Common.checkForTagAndCreateReader(context);

		if (mcReader != null) {
			// Le secteur doit etre compris entre 0 et le nombre de secteur-1
			if (sector < 0 && sector > mcReader.getSectorCount() - 1) {
				System.out.println("le secteur doit etre compris entre 0 et mcReader.getSectorCount()-1 ");
				mcReader.close();
				return false;
			}

			// Si le secteur 0 est s�lectionn� on peut �crire que 32 bytes (
			// bloc 2
			// et 3)
			if (sector == 0) {
				if (Common.isHexAnd32Byte(data, context) == false) {
					mcReader.close();
					System.out.println("SECTOR 0 :: 32 BYTES");
					return false;
				}

			} else if (Common.isHexAnd48Byte(data, context) == false) {
				// autres secteurs, 48 bytes
				System.out.println("SECTOR 0 :: 48 BYTES");
				mcReader.close();
				return false;
			}

			int i = 0;

			if (sector == 0) {
				for (int j = 1; j < 3; j++) {
					mcReader.close();
					mcReader.connect();
					String string = (data.subSequence(i, i + 32).toString());
					System.out.println(string);
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
					System.out.println(string);
					result = mcReader.writeBlock(sector, j, Common.hexStringToByteArray(string), key, useAsKeyB);
					mcReader.close();
					if (result != 0) {
						return false;
					}
					i = i + 32;
				}
			}

			if (result == 0) {
				System.out.println("TRUE");
				Toast.makeText(context, "Transmission Effectu�", Toast.LENGTH_SHORT).show();
				return true;
			}
		}
		// System.out.println("FALSE");
		Toast.makeText(context, "Pas de connection", Toast.LENGTH_SHORT).show();
		return false;

	}

	/**
	 * Ecire dans tout l'espace de la puce NFC (752bytes pour la MifareClassic 1K) Pour cette fonction il faut que tout les secteurs ont la m�me Key
	 * 
	 * @param data : Donn�es � transmettre (String d'hexad�cimaux)
	 * @param key : cl� permettant l'authentification pour �crire
	 * @param useAsKeyB : true si on utilise la keyB false sinon
	 * @param context
	 * @return true si les donn�es on bien �t� transmise
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
			System.out.println("nombre de block : " + count);

			
			if (data.length() < 1504) {
				while (data.length() != 1504) {
					data = data + "0";
				}
			}

			if (!(Common.isHexAnd752Byte(data, context))) {
				mcReader.close();
				Toast.makeText(context, "Donn�es �ronn�es", Toast.LENGTH_SHORT).show();
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
						System.out.println("s : " + j + "b : " + i + " data : " + string);
						result = mcReader.writeBlock(j, i, Common.hexStringToByteArray(string), key, useAsKeyB);
						mcReader.close();
						if (result != 0) {
							Toast.makeText(context, "Error Sector : "+j+" Block : "+i, Toast.LENGTH_SHORT).show();
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
						System.out.println("s : " + j + "b : " + i + " data : " + string);
						result = mcReader.writeBlock(j, i, Common.hexStringToByteArray(string), key, useAsKeyB);
						mcReader.close();
						if (result != 0) {
							Toast.makeText(context, "Error Sector : "+j+" Block : "+i, Toast.LENGTH_SHORT).show();
							return false;
						}
						k = k + 32;
					}
				}
			}

			if (result == 0) {
				System.out.println("TRUE");
				Toast.makeText(context, "Donn�es transmises  ", Toast.LENGTH_SHORT).show();
				return true;
			}
		}
		Toast.makeText(context, "Pas de connection", Toast.LENGTH_SHORT).show();
		return false;

	}

	
	/**
	 * Ecire dans tout l'espace de la puce NFC (752bytes pour la MifareClassic 1K) Pour cette fonction il faut que tout les secteurs ont la m�me Key
	 * 
	 * @param data : Donn�es � transmettre (String d'hexad�cimaux)
	 * @param key : cl� permettant l'authentification pour �crire
	 * @param useAsKeyB : true si on utilise la keyB false sinon
	 * @param context
	 * @return true si les donn�es on bien �t� transmise
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
			System.out.println("nombre de block : " + count);

			
			if (data.length() < 1504) {
				while (data.length() != 1504) {
					data = data + "0";
				}
			}

			if (!(Common.isHexAnd752Byte(data, context))) {
				mcReader.close();
				Toast.makeText(context, "Donn�es �ronn�es", Toast.LENGTH_SHORT).show();
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
						System.out.println("s : " + j + "b : " + i + " data : " + string);
						result = mcReader.writeBlock(j, i, Common.hexStringToByteArray(string), key[j], useAsKeyB);
						mcReader.close();
						if (result != 0) {
							Toast.makeText(context, "Error Sector : "+j+" Block : "+i, Toast.LENGTH_SHORT).show();
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
						System.out.println("s : " + j + "b : " + i + " data : " + string);
						result = mcReader.writeBlock(j, i, Common.hexStringToByteArray(string), key[j], useAsKeyB);
						mcReader.close();
						if (result != 0) {
							Toast.makeText(context, "Error Sector : "+j+" Block : "+i, Toast.LENGTH_SHORT).show();
							return false;
						}
						k = k + 32;
					}
				}
			}

			if (result == 0) {
				System.out.println("TRUE");
				Toast.makeText(context, "Donn�es transmises  ", Toast.LENGTH_SHORT).show();
				return true;
			}
		}
		Toast.makeText(context, "Pas de connection", Toast.LENGTH_SHORT).show();
		return false;

	}
	
	
	
	
	/**
	 * Ecriture des AccesBits du Sector Trailer en utilisant la cl� A et la cl� B
	 * 
	 * @param sector : num�ro du secteur dont on souhaite changer les AccessBits
	 * @param keyA : Key A actuelle
	 * @param keyB : Key B actuelle
	 * @param newAccessBit : Nouveau AccesBits du SectorTrailer
	 * @return true si l'�criture c'est bien pass�
	 * @throws ActionNotAllowed : Action non permise
	 */
	public boolean writeAccesBit(int sector, byte[] keyA, byte[] keyB, byte[] newAccessBit, Context context) throws ActionNotAllowed {

		// r�cup�ration du Secteur Trailer du secteur voulu
		String result = this.readABlock(sector, 3, keyA, false, context);

		if (result != null) {
			// R�cup�ration des param�tres pour le secteur
			byte[] ac = Common.hexStringToByteArray(result.subSequence(12, 20).toString());
			byte[][] AC = Common.acToACMatrix(ac);

			// Lecture des permissions sur le sector Trailer
			int permission = this.ReadAccesBits(AC[0][3], AC[1][3], AC[2][3], true);

			// V�rification des permissions afin de connaitre si on peut effectuer cette action
			if (!(permission == 13 || permission == 14 || permission == 15)) {
				throw new ActionNotAllowed("We can't write AccesBits with this parameters");
			}
			if (permission == 13) {
				String bloc = Common.byte2HexString(keyA) + Common.byte2HexString(newAccessBit) + result.substring(20, 32);
				System.out.println("nouveau sector Trailer ::: " + bloc);
				// : Write with KEY A
				this.writeInABlock(sector, 3, bloc, keyA, false, context);
			} else if (permission == 14 || permission == 15) {
				// : Write with KEY B
				String bloc = Common.byte2HexString(keyA) + Common.byte2HexString(newAccessBit) + Common.byte2HexString(keyB);
				System.out.println("nouveau sector Trailer ::: " + bloc);
				this.writeInABlock(sector, 3, bloc, keyB, true, context);
			}

		}
		Toast.makeText(context, "Pas de connection", Toast.LENGTH_SHORT).show();
		return false;
	}

	/**
	 * Ecriture des AccesBits du Sector Trailer en utilisant la cl� A ou la cl� B
	 * 
	 * @param sector : num�ro du secteur dont on souhaite changer les AccessBits
	 * @param keyA : Key A actuelle
	 * @param keyB : Key B actuelle
	 * @param newAccessBit : Nouveau AccesBits du SectorTrailer
	 * @return true si l'�criture c'est bien pass�
	 * @throws ActionNotAllowed : Action non permise
	 * @throws KeyAIsRequired : Cl� A est requise pour effectuer cette op�ration
	 * @throws KeyBAndAIsRequired : la cl� A et la cl� B sont requise pour effectuer cette op�ration
	 */
	public boolean writeAccesBit(int sector, byte[] key, boolean useAsKeyB, byte[] newAccessBit, Context context) throws ActionNotAllowed,
			KeyAIsRequired, KeyBAndAIsRequired {

		// r�cup�ration du Secteur Trailer du secteur voulu
		String result = this.readABlock(sector, 3, key, useAsKeyB, context);

		if (result != null) {
			// R�cup�ration des param�tres pour le secteur
			byte[] ac = Common.hexStringToByteArray(result.subSequence(12, 20).toString());
			byte[][] AC = Common.acToACMatrix(ac);

			// Lecture des permissions sur le sector Trailer
			int permission = this.ReadAccesBits(AC[0][3], AC[1][3], AC[2][3], true);

			// V�rification des permissions afin de connaitre si on peut effectuer cette action
			if (!(permission == 13 || permission == 14 || permission == 15)) {
				throw new ActionNotAllowed("We can't write AccesBits with this parameters");
			}
			if (permission == 13 && useAsKeyB == true) {
				throw new KeyAIsRequired();
			} else if (permission == 14 || permission == 15) {
				throw new KeyBAndAIsRequired();
			}

			if (permission == 13 && useAsKeyB == false) {
				// : Write with KEY A
				String bloc = Common.byte2HexString(key) + Common.byte2HexString(newAccessBit) + result.substring(21, 32);
				System.out.println("nouveau sector Trailer ::: " + bloc);
				this.writeInABlock(sector, 3, bloc, key, false, context);
			}

		}
		return false;
	}

	/**
	 * Ecriture de la Cl� A
	 * 
	 * @param sector : Num�ro du secteur dont on souhaite changer la cl� A
	 * @param key : Cl� avec laquelle on souhaite acc�der au secteurTrailer
	 * @param newKey : Nouvelle cl� A
	 * @return : true si l'op�ration d'�criture c'est bien pass�
	 * @throws KeyBIsRequired : La cl� B est requise pour faire cette op�ration
	 * @throws KeyAIsRequired : La cl� A est requise pour faire cette op�ration
	 */
	public boolean writeKeyA(int sector, byte[] key, boolean useAsKeyB, byte[] newKeyA, Context context) throws ActionNotAllowed, KeyBIsRequired,
			KeyAIsRequired {

		// r�cup�ration du Secteur Trailer du secteur voulu
		String result = this.readABlock(sector, 3, key, useAsKeyB, context);

		if (result != null) {
			// R�cup�ration des param�tres pour le secteur
			byte[] ac = Common.hexStringToByteArray(result.subSequence(12, 20).toString());
			byte[][] AC = Common.acToACMatrix(ac);
			// System.out.println(ac[0] + "  " + ac[1] + "  " + ac[2] + "  " + ac[3]);
			// System.out.println(AC[0][3] + "   " + AC[2][3] + "     " + AC[2][3]);

			// Lecture des permissions sur le sector Trailer
			int permission = this.ReadAccesBits(AC[0][3], AC[2][3], AC[2][3], true);

			// V�rification des permissions afin de connaitre si on peut effectuer cette action
			if (!(permission == 9 || permission == 11 || permission == 13 || permission == 14)) {
				throw new ActionNotAllowed("We can't write KEYA with this parameters");
			}

			if ((permission == 11 || permission == 14) && useAsKeyB == false) {
				throw new KeyBIsRequired();
			}

			if ((permission == 9 || permission == 13) && useAsKeyB == true) {
				throw new KeyAIsRequired();

			}

			// Si Permission = 9 ou 13 alors on peut �crire la nouvelle cl� B
			if (permission == 9 || permission == 13) {
				String bloc = Common.byte2HexString(newKeyA) + result.subSequence(12, 32);
				System.out.println("Nouveau Bloc ::: " + bloc);
				System.out.println("Ancien  Bloc ::: " + result);
				// : key A
				this.writeInABlock(sector, 3, bloc, key, false, context);
			} else if (permission == 11 || permission == 14) {
				String bloc = Common.byte2HexString(newKeyA) + result.subSequence(12, 20) + Common.byte2HexString(key);
				System.out.println("Nouveau Bloc 2 ::: " + bloc);
				System.out.println("Ancien  Bloc 2 ::: " + result);
				// : key b
				this.writeInABlock(sector, 3, bloc, key, true, context);
			}
		}
		return false;
	}

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
	public boolean writeKeyB(int sector, byte[] key, boolean useAsKeyB, byte[] newKeyB, Context context) throws ActionNotAllowed, KeyBIsRequired,
			KeyAIsRequired, KeyBAndAIsRequired {

		// r�cup�ration du Secteur Trailer du secteur voulu
		String result = this.readABlock(sector, 3, key, useAsKeyB, context);

		if (result != null) {
			// R�cup�ration des param�tres pour le secteur
			byte[] ac = Common.hexStringToByteArray(result.subSequence(12, 20).toString());
			byte[][] AC = Common.acToACMatrix(ac);

			// System.out.println(ac[0] + "  " + ac[1] + "  " + ac[2] + "  " + ac[3]);
			// System.out.println(AC[0][3] + "   " + AC[2][3] + "     " + AC[2][3]);

			// Lecture des permissions sur le sector Trailer
			int permission = this.ReadAccesBits(AC[0][3], AC[1][3], AC[2][3], true);

			// V�rification des permissions afin de connaitre si on peut effectuer cette action
			if (!(permission == 9 || permission == 11 || permission == 13 || permission == 14)) {
				throw new ActionNotAllowed("We can't write KEYA with this parameters");
			}

			if ((permission == 11 || permission == 14)) {
				throw new KeyBAndAIsRequired();
			}

			if ((permission == 9 || permission == 13) && useAsKeyB == true) {
				throw new KeyAIsRequired();

			}

			// Si Permission = 9 ou 13 alors on peut �crire la nouvelle cl� B
			if (permission == 9 || permission == 13) {
				String bloc = Common.byte2HexString(key) + result.subSequence(12, 20) + Common.byte2HexString(newKeyB);
				System.out.println("Nouveau Bloc ::: " + bloc);
				System.out.println("Ancien  Bloc ::: " + result);
				// : avec key A
				this.writeInABlock(sector, 3, bloc, key, false, context);
				return true;
			}

		}
		return false;
	}

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
	public boolean writeKeyB(int sector, byte[] keyA, byte[] keyB, byte[] newKeyB, Context context) throws ActionNotAllowed {

		String result = this.readABlock(sector, 3, keyA, false, context);

		if (result != null) {

			byte[] ac = Common.hexStringToByteArray(result.subSequence(12, 20).toString());

			System.out.println(ac[0] + "  " + ac[1] + "  " + ac[2] + "  " + ac[3]);
			byte[][] AC = Common.acToACMatrix(ac);
			System.out.println(AC[0][3] + "   " + AC[2][3] + "     " + AC[2][3]);
			int permission = this.ReadAccesBits(AC[0][3], AC[2][3], AC[2][3], true);

			if (!(permission == 9 || permission == 11 || permission == 13 || permission == 14)) {
				throw new ActionNotAllowed("We can't write KEYA with this parameters");
			}

			if (permission == 9 || permission == 13) {
				String bloc = Common.byte2HexString(keyA) + result.subSequence(12, 20) + Common.byte2HexString(newKeyB);
				System.out.println("Nouveau Bloc ::: " + bloc);
				System.out.println("Ancien  Bloc ::: " + result);
				// ecrire avec cl� A
				this.writeInABlock(sector, 3, bloc, keyA, false, context);
				return true;
			} else if (permission == 11 || permission == 14) {
				String bloc = Common.byte2HexString(keyA) + result.subSequence(12, 20) + Common.byte2HexString(newKeyB);
				System.out.println("Nouveau Bloc ::: " + bloc);
				System.out.println("Ancien  Bloc ::: " + result);
				// ecrire avec cl� B
				this.writeInABlock(sector, 3, bloc, keyB, true, context);
				return true;
			}

		}
		return false;
	}

	// ////////////////////////////////////////////////////////////

	// Fonctions lectures de la puce

	// ////////////////////////////////////////////////////////////

	/**
	 * Obtenir le Num�ro ID du tag
	 * 
	 * @return ID du TAG (String)
	 */
	public String getId() {
		MCReader mcReader = Common.checkForTagAndCreateReader(null);
		if (mcReader != null) {
			mcReader.close();
			return Common.byte2HexString(Common.getUID());
		}
		return "No ID discovered";
	}

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
	public String readABlock(int sector, int block, byte[] key, boolean useAsKeyB, Context context) {

		MCReader mcReader = Common.checkForTagAndCreateReader(context);
		String[] string2 = null;
		// * Lecture du bloc
		if (mcReader != null) {

			try {
				string2 = mcReader.readSector(sector, key, useAsKeyB);
				mcReader.close();
			} catch (TagLostException e) {
				e.printStackTrace();
			}
			if (string2 != null) {
				return string2[block];
			}

		}
		Toast.makeText(context, "Pas de connection avec le TAG", Toast.LENGTH_SHORT).show();
		return null;
	}

	/**
	 * Lecture d'un secteur
	 * 
	 * @param sector : Num�ro du secteur que l'on souhaite lire
	 * @param key : cl� permettant l'authentification pour �crire
	 * @param useAsKeyB : true si on utilise la keyB false sinon
	 * @param context
	 * @return data (String de hexad�cimale)
	 */
	public String readASector(int sector, byte[] key, boolean useAsKeyB, Context context) {

		// se connecter � la puce NFC
		MCReader mcReader = Common.checkForTagAndCreateReader(context);

		if (mcReader != null) {
			// * Lecture bloc par bloc de la puce NFC avec cl� par d�faut

			String[] dataPuce = null;

			try {
				dataPuce = mcReader.readSector(sector, key, useAsKeyB);
			} catch (TagLostException e) {
				e.printStackTrace();
			}

			String data = "";

			for (int j = 0; j < mcReader.getBlockCountInSector(sector); j++) {
				data += dataPuce[j]; // + "\0A"
			}
			
			mcReader.close();

			System.out.println(data);
			return data;
		}
		Toast.makeText(context, "Pas de connection", Toast.LENGTH_SHORT).show();
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
		// se connecter � la puce NFC
		MCReader mcReader = Common.checkForTagAndCreateReader(context);

		// * Lecture bloc par bloc de la puce NFC avec cl� par d�faut

		String[][] string = new String[100][4];

		String[] string2 = null;
		if (mcReader != null) {

			for (int i = 0; i < mcReader.getSectorCount() - 1; i++) {
				try {
					string2 = mcReader.readSector(i, MifareClassic.KEY_DEFAULT, false);
				} catch (TagLostException e) {
					e.printStackTrace();
				}
				string[i][0] = string2[0];
				string[i][1] = string2[1];
				string[i][2] = string2[2];
				string[i][3] = string2[3];

			}

			String data = "";
			for (int i = 0; i < mcReader.getSectorCount() - 1; i++) {

				for (int j = 0; j < mcReader.getBlockCountInSector(i); j++) {
					data += string[i][j];// + "0A";
				}
				// data += "0A";

			}

			mcReader.close();

			System.out.println(data);
			return data;
		}
		Toast.makeText(context, "Pas de connection", Toast.LENGTH_SHORT).show();
		return null;

	}

	/**
	 * R�cup�re le nombre de bloc dans le TAG NFC
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
	 * R�cup�re le nombre de secteur du tag NFC
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
	 * R�cup�re le nombre de block dans le secteur en param�tre du tag NFC
	 * 
	 * @param sector : index du secteur dont on souhaite connaitre le nombre de bloc
	 * @return le nombre de bloc dans le secteur demand�
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
	 * @param sector : Num�ro du secteur qui contient le bloc dont on veutdes informations
	 * @param block : Num�ro du bloc dont on veut obtenir les informations
	 * @param key : Cl� pour acc�der aux donn�es
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

		// Lecture du sector Trailer du Secteur demand�
		String result = this.readABlock(sector, 3, key, useAsKeyB, null);

		if (result != null) {
			// R�cup�ration des param�tres pour le secteur
			byte[] ac = Common.hexStringToByteArray(result.subSequence(12, 20).toString());
			byte[][] AC = Common.acToACMatrix(ac);

			boolean trailer;
			if (block != 3) {
				trailer = false;
			} else {
				trailer = true;
			}
			// lecture des permissions pour le block demand�
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
	public byte[] createAccessBit(int permB0, int permB1, int permB2, int permSectorTrailer) {

		String[] block0 = getAccesbit(permB0);
		String[] block1 = getAccesbit(permB1);
		String[] block2 = getAccesbit(permB2);
		String[] block3 = getAccesbit(permSectorTrailer);

		String Sector = binaryToHexa(not(block3[1]) + not(block2[1]) + not(block1[1]) + not(block0[1]))
				+ binaryToHexa(not(block3[0]) + not(block2[0]) + not(block1[0]) + not(block0[0]))
				+ binaryToHexa(block3[0] + block2[0] + block1[0] + block0[0])
				+ binaryToHexa(not(block3[2]) + not(block2[2]) + not(block1[2]) + not(block0[2]))
				+ binaryToHexa(block3[2] + block2[2] + block1[2] + block0[2]) + binaryToHexa(block3[1] + block2[1] + block1[1] + block0[1]) + "69";
		System.out.println(Sector);

		return Common.hexStringToByteArray(Sector);

	}

	/**
	 * R�cup�re les 3 bits d'AccessBit pour une permission
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
	 * Convertir une chaine hexad�cimale en une chaine de caract�re
	 * 
	 * @param s : chaine hexad�cimale � convertir
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
	 * Convertir un caract�re en d�cimal
	 * 
	 * @param ch : charact�re � convertir
	 * @return valeur du caract�re en d�cimal
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
	 * Convertir une chaine de caract�re en une chaine hexad�cimale
	 * 
	 * @param arg : chaine de charact�re
	 * @return chaine en hexad�cimale
	 */
	public String toHex(String arg) {
		return String.format("%x", new BigInteger(1, arg.getBytes(Charset.defaultCharset())));
	}

	/**
	 * Convert une chaine binaire de 4 bits en un hexad�cimal
	 * 
	 * @param binary Chaine de 4 bits
	 * 
	 * @return hexad�cimale
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

}
