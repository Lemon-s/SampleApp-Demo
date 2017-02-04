//
//  TutorialAppException.h
//  TutorialApp
//
//  Created by Khachatur on 8/4/15.
//  Copyright (c) 2015 . All rights reserved.
//

#ifndef TutorialApp_TutorialAppException_h
#define TutorialApp_TutorialAppException_h

#include <string>

enum ExceptionClass {
  
    /**
     * The operation was canceled by user.
     * Functions:
     *      TutorialAppException()
     * Conditions:
     *      The user declined any necessary part of the interaction to complete the registration.
     */
    EXCEPTION_TYPE_CANCELED,
    
    /**
     * No matching authentication method is found to process the request.
     * Functions:
     *      TutorialAppException()
     * Conditions:
     *      No authenticator matching the authenticator policy specified in the Protocol Message is available to service the request, or the user declined to consent to the use of a suitable authenticator.
     */
    EXCEPTION_TYPE_NO_MATCH,
    
    /**
     * Connection error.
     * Functions:
     *      TutorialAppException()
     */
    EXCEPTION_TYPE_CONNECTION_ERROR,
    
    /**
     * Server error.
     * Functions:
     *      TutorialAppException()
     */
    EXCEPTION_TYPE_SERVER_ERROR,
    
    /**
     * Client error.
     * Functions:
     *      TutorialAppException()
     */
    EXCEPTION_TYPE_CLIENT_ERROR
};

/**
 @class TutorialAppException
 
 Thrown when in TutorialApp appears failure or when need pass information.
 */
class TutorialAppException {
public:
    TutorialAppException(const std::string& typeException,
                         const std::string& whatMsg,
                         ExceptionClass     exceptionClass
                         )
        : m_msgException(whatMsg.c_str())
        , m_typeException(typeException)
        , m_exceptionClass(exceptionClass)
    {  }
    
    const char* what() const throw()
    {
        return m_msgException.c_str();
    }
    
    /// @returns type of Exception, which can be Error, Info and Warning
    std::string GetTypeException() { return m_typeException; }
    
    /// @returns class of exception
    ExceptionClass GetExceptionClass() { return m_exceptionClass; }
    
private:
    const std::string   m_typeException;
    const std::string   m_msgException;
    ExceptionClass      m_exceptionClass;
}; //class TutorialAppException


#endif
