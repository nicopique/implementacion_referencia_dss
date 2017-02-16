
package procesamiento;

import com.gemalto.ics.rnd.egov.dss.sdk.verify.DSSResult;
import com.gemalto.ics.rnd.egov.dss.sdk.verify.DSSResultSuccess;
import com.gemalto.ics.rnd.egov.dss.sdk.verify.api.DefaultResponseParserFactory;
import com.gemalto.ics.rnd.egov.dss.sdk.verify.api.ResponseParser;
import com.gemalto.ics.rnd.egov.dss.sdk.verify.signature.JCAKeyStoreTrustStore;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.security.Security;
import java.util.Properties;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.tomcat.util.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author piquerez
 */
public class respuestaDSS extends HttpServlet {

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
        propiedades.load(respuestaDSS.class.getResourceAsStream("configuracion.properties"));
        
        Security.addProvider(new BouncyCastleProvider());
        InputStream ts = new FileInputStream(propiedades.getProperty("trustore_ruta"));
        
        JCAKeyStoreTrustStore trustStore= new JCAKeyStoreTrustStore("BC",propiedades.getProperty("trustore_tipo"),ts,propiedades.getProperty("trustore_pass"),propiedades.getProperty("trustore_alias"));
                
        ResponseParser responseParser = DefaultResponseParserFactory.getResponseParser(trustStore, null);
        
        String signResponseBase64 = request.getParameterValues("SignResponse")[0];
        String responseDocument = new String(Base64.decodeBase64(signResponseBase64));
       

        DSSResult result = responseParser.parseAndGetResult(responseDocument);
        
        if (result instanceof DSSResultSuccess) {
            byte[] documento= ((DSSResultSuccess) result).getDocumentData();
            //Convertir arreglo de bytes en archivo
            FileOutputStream salida = new FileOutputStream(propiedades.getProperty("pdf_ruta_guardar")+result.getRequestId()+".pdf"); 
            salida.write(documento);
            salida.close();
            
             
        }

        try (PrintWriter out = response.getWriter()) {
            out.println("<!DOCTYPE html>");
            out.println("<html>");
            out.println("<head>");
            out.println("<title>Servlet respuestaDSS</title>");            
            out.println("</head>");
            out.println("<body>");
            //out.println("<h1>Servlet respuestaDSS at " + request.getContextPath() + "</h1>");
            out.println("<h1>Verificación de respuesta</h1>");
            out.println("<p> Request Id: "+ result.getRequestId() +"</p>");
            out.println("<p> Major result: "+ result.getResultMajor()+"</p>");
            out.println("<p> Message: "+ result.getResultMessage()+"</p>");
            out.println("<p> MessageLang: "+ result.getResultMessageLang()+"</p>");
            out.println("<p> Minor Result: "+ result.getResultMinor()+"</p>");
            out.println("<a href=\"/\">Volver a Realizar pedido DSS</a>");
            out.println("</body>");
            out.println("</html>");
            ts.close();
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
        return "Short description";
    }// </editor-fold>

}
