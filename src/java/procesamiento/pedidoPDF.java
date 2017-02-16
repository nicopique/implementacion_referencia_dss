
package procesamiento;

import com.gemalto.ics.rnd.egov.dss.sdk.create.api.RequestBuilderImpl;
import com.gemalto.ics.rnd.egov.dss.sdk.create.key.JCAKeyStoreSignatureKeyService;
import com.gemalto.ics.rnd.egov.dss.sdk.create.model.pades.VisibleSignature;
import com.gemalto.ics.rnd.egov.dss.sdk.create.signature.XmlDSigRequestSigner;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.tomcat.util.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author piquerez
 */
public class pedidoPDF extends HttpServlet {
    
  

    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        
        Properties propiedades = new Properties();
        propiedades.load(pedidoPDF.class.getResourceAsStream("configuracion.properties"));
        
        /*Creación del builder Implementation*/
        
        Security.addProvider(new BouncyCastleProvider());
        InputStream ks = new FileInputStream(propiedades.getProperty("keystore_firma_ruta"));
        JCAKeyStoreSignatureKeyService jcaKeyStoreSignatureKeyService = new JCAKeyStoreSignatureKeyService("BC",propiedades.getProperty("keystore_firma_tipo"),ks,propiedades.getProperty("keystore_firma_pass"),propiedades.getProperty("keystore_firma_alias"));
        
        
        XmlDSigRequestSigner xmlDSigRS = new XmlDSigRequestSigner();
        xmlDSigRS.setDigestMethod("http://www.w3.org/2001/04/xmlenc#sha256");
        xmlDSigRS.setSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        
        RequestBuilderImpl requestBuilder = new RequestBuilderImpl(
            jcaKeyStoreSignatureKeyService, xmlDSigRS,
            "tallerDSS", "http://tallerDSS.uy:8081/tallerDSS/respuestaDSS");
            requestBuilder.setSignatureMethods(Collections.singletonList("SmartCard"));
        
        String requestData = "";
        
        String requestId="";  //identifier of OASIS DSS request
        /*Generación de numero aleatorio*/
        SecureRandom secureRandom = new SecureRandom();
        double random = secureRandom.nextDouble();
        int randomInt = (int)(random*1000000);
        requestId = ""+random;
        
        String targetURL = "https://eid.portal.gub.uy/dss/dss/post";
        
        //requestData = requestBuilder.buildCMSSignRequest(requestId, "Texto a firmar para el taller.".getBytes(), true);
        
        
        Path path = Paths.get("/Users/piquerez/Pruebas/TestDSS/pdf_sin_firmar.pdf");
        byte[] documento=Files.readAllBytes(path);
            
          
        Map<String,byte[]> signedAttributes = new HashMap<String, byte[]>(); //Atributos
       
        /*
        for(SignCAdESModel.AttributeHolder holder:signPAdESModel.getSignedAttributes()){
            if (holder.isInclude()) {
                attributeMap.put(holder.getURI(), Base64.decodeBase64(holder.getAttributeData()));
            }
        }
        
        */
        String signatureForm = "urn:oasis:names:tc:dss:1.0:profiles:AdES:forms:BES";
        
        VisibleSignature vSignature = new VisibleSignature();
        requestData = requestBuilder.buildPAdESBasicSignRequest(requestId, documento, signedAttributes,signatureForm,vSignature);
   
        
        /*Datos del POST*/
        
        
        
        
        try (PrintWriter out = response.getWriter()) {
            /* TODO output your page here. You may use following sample code. */
            out.println("<!DOCTYPE html>");
            out.println("<html>");
            out.println("<head>");
            out.println("<title>Servlet pedidoDSS</title>");            
            out.println("</head>");
            out.println("<body>");
            //out.println("<h1>Servlet pedidoDSS at " + request.getContextPath() + "</h1>");
            out.println("<form action=\""+targetURL+"\" method=\"post\">");
            out.println("<input type=\"hidden\" name=\"SignRequest\" value=\""+ StringEscapeUtils.escapeHtml4(Base64.encodeBase64String(requestData.getBytes("UTF-8")))  +"\" />");
            out.println("<input type=\"submit\" value=\"Enviar documento a firmar\">");
            out.println("</form>");
            out.println("</body>");
            out.println("</html>");
            ks.close();
        }
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Servlet que realia pedidos DSS";
    }// </editor-fold>

}
