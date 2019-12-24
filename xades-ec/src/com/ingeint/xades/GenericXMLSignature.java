/*
 *  Copyright (C) 2015 VirtualSAMI Cia. Ltda. <amanda@virtualsami.com.ec>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.ingeint.xades;


import es.mityc.firmaJava.libreria.utilidades.UtilidadTratarNodo;
import es.mityc.firmaJava.libreria.xades.DataToSign;
import es.mityc.firmaJava.libreria.xades.FirmaXML;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.IPassStoreKS;
import es.mityc.javasign.pkstore.keystore.KSStore;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.ingeint.keystore.PassStoreKS;



/**
 * GenericXMLSignature
 *
 * Descripción:
 *
 * @author Alcides Rivera <alcides@virtualsami.com.ec>
 * @author Orlando Curieles </orlando.curieles@ingeint.com>
 * @version 0.1
 */
public abstract class GenericXMLSignature {

    private static final String ID_CE_CERTIFICATE_POLICIES = "2.5.29.32";
    public static InputStream PKCS12_RESOURCE;
    public static String PKCS12_PASSWORD;
    public static final String OUTPUT_DIRECTORY = ".";

    public GenericXMLSignature(String pkcs12, String pkcs12_password) {
        byte[] decoded_sign = Base64.decodeBase64(pkcs12.getBytes());
        String decodedString_sign = new String(decoded_sign);

        InputStream arch = null;
        try {
            arch = new FileInputStream(decodedString_sign);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(GenericXMLSignature.class.getName()).log(Level.SEVERE, null, ex);
        }
        byte[] decoded = Base64.decodeBase64(pkcs12_password.getBytes());
        String decodedString = new String(decoded);
        PKCS12_RESOURCE = arch;

        PKCS12_PASSWORD = decodedString;
    }

    public GenericXMLSignature() {
    }

    protected Document execute() throws Exception {
        IPKStoreManager storeManager = getPKStoreManager();
        if (storeManager == null) {
            System.err.println("El gestor de claves no se ha obtenido correctamente.");
            return null;
        }
        X509Certificate certificate = getFirstCertificate(storeManager);
        if (certificate == null) {
            System.err.println("No existe ningún certificado para firmar.");
            return null;
        }
        PrivateKey privateKey;
        try {
            privateKey = storeManager.getPrivateKey(certificate);
        } catch (CertStoreException e) {
            System.err.println("Error al acceder al almacén.");
            return null;
        }
        Provider provider = storeManager.getProvider(certificate);

        DataToSign dataToSign = createDataToSign();

        FirmaXML sign = new FirmaXML();

        Document docSigned = null;
        try {
            Object[] res = sign.signFile(certificate, dataToSign, privateKey, provider);
            return (Document) res[0];
        } catch (Exception ex) {
            System.err.println("Error realizando la firma");
            ex.printStackTrace();
        }
        return null;
    }

    protected abstract DataToSign createDataToSign();

    protected abstract String getSignatureFileName();

    private void saveDocumentToFile(Document document, String pathfile) {
        try {
            FileOutputStream fos = new FileOutputStream(pathfile);
            UtilidadTratarNodo.saveDocumentToOutputStream(document, fos, true);
        } catch (FileNotFoundException e) {
            System.err.println("Error al guardar el documento");
            e.printStackTrace();
            System.exit(-1);
        }
    }

    private void saveDocumentToFileUnsafeMode(Document document, String pathfile) {
        TransformerFactory tfactory = TransformerFactory.newInstance();
        try {
            Transformer serializer = tfactory.newTransformer();

            serializer.transform(new DOMSource(document), new StreamResult(new File(pathfile)));
        } catch (TransformerException e) {
            System.err.println("Error al guardar el documento");
            e.printStackTrace();
            System.exit(-1);
        }
    }

    protected Document getDocument(String resource) {
        Document doc = null;
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        try {
            doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(resource)));
        } catch (ParserConfigurationException ex) {
            System.err.println("Error al parsear el documento");
            ex.printStackTrace();
            System.exit(-1);
        } catch (SAXException ex) {
            System.err.println("Error al parsear el documento");
            ex.printStackTrace();
            System.exit(-1);
        } catch (IOException ex) {
            System.err.println("Error al parsear el documento");
            ex.printStackTrace();
            System.exit(-1);
        } catch (IllegalArgumentException ex) {
            System.err.println("Error al parsear el documento");
            ex.printStackTrace();
            System.exit(-1);
        }
        return doc;
    }

    protected String getDocumentAsString(String resource) {
        Document doc = getDocument(resource);
        TransformerFactory tfactory = TransformerFactory.newInstance();

        StringWriter stringWriter = new StringWriter();
        try {
            Transformer serializer = tfactory.newTransformer();
            serializer.transform(new DOMSource(doc), new StreamResult(stringWriter));
        } catch (TransformerException e) {
            System.err.println("Error al imprimir el documento");
            e.printStackTrace();
            System.exit(-1);
        }
        return stringWriter.toString();
    }

    private IPKStoreManager getPKStoreManager() {
        IPKStoreManager storeManager = null;
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");

            ks.load(PKCS12_RESOURCE, PKCS12_PASSWORD.toCharArray());
            storeManager = new KSStore(ks, (IPassStoreKS) new PassStoreKS(PKCS12_PASSWORD));
        } catch (KeyStoreException ex) {
            System.err.println("No se puede generar KeyStore PKCS12");
            ex.printStackTrace();
            System.exit(-1);
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("No se puede generar KeyStore PKCS12");
            ex.printStackTrace();
            System.exit(-1);
        } catch (CertificateException ex) {
            System.err.println("No se puede generar KeyStore PKCS12");
            ex.printStackTrace();
            System.exit(-1);
        } catch (IOException ex) {
            System.err.println("No se puede generar KeyStore PKCS12");
            ex.printStackTrace();
            System.exit(-1);
        }
        return storeManager;
    }

    /**
     * <p>
     * Recupera el primero de los certificados del almacén que contenga políticas
     * <b>id-ce-certificatePolicies</b> con ID <b>2.5.29.32</b>.
     * </p>
     *
     * @param storeManager
     *            Interfaz de acceso al almacén
     * @return Primer certificado disponible en el almacén
     * @throws Exception
     *             cuando el almacen está vacío o no se encuentran certificados con
     *             políticas.
     */
    private X509Certificate getFirstCertificate(final IPKStoreManager storeManager) throws Exception {
        try {
            List<X509Certificate> certs = storeManager.getSignCertificates();
            if (isNull(certs) || certs.isEmpty()) {
                throw  new Exception("La lista de certificados se encuentra vacía.");
            }
            X509Certificate certificate = certs.stream().filter(this::hasCertificatePolicies).findFirst()
                    .orElseThrow(() -> new Exception("No se encontró ningún certificado con políticas"));
            return certificate;
        } catch (CertStoreException ex) {
            throw new Exception(ex);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * <p>
     * Verifica la existencia de políticas en el certificado utilizando el campo
     * <b>id-ce-certificatePolicies</b> con ID <b>2.5.29.32</b>.
     * </p>
     *
     * @param certificate
     *            certificado a examinar
     * @return true si encuentra políticas, false si no encuentra políticas o el
     *         certificado es nulo
     */
    private boolean hasCertificatePolicies(X509Certificate certificate) {
        if (nonNull(certificate)) {
            byte[] certificatePolicies = certificate.getExtensionValue(ID_CE_CERTIFICATE_POLICIES);
            if (certificatePolicies != null && certificatePolicies.length > 0) {
                return true;
            }
        }
        return false;
    }
}
