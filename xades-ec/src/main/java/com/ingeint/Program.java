package com.ingeint;

import com.ingeint.xades.XAdESBESSignature;
import org.w3c.dom.Document;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;

public class Program {

    public static String getStringFromDocument(Document document) {
        try {
            DOMSource domSource = new DOMSource(document);
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.transform(domSource, result);
            return writer.toString();
        } catch (TransformerException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println(" ERROR: el xml, archivo y password son obligatorios");
            return;
        }

        String file = args[0];
        String sign = args[1];
        String password = args[2];

        XAdESBESSignature signer = new XAdESBESSignature(file, sign, password);

        System.out.println(getStringFromDocument(signer.signDocument()));
    }
}