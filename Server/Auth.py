class Auth:
    def __init__(self,quiz):
        self.__challenge = True
        self.__response = False
        self.__sha384 = ""
        self.__quizz = quiz
        self.__sharedSecret = ""

    def isChallengeComplete(self):
        return self.__challenge

    def isResponseComplete(self):
        return self.__response

    def getSha384(self):
        return self.__sha384

    def getQuizz(self):
        return self.__quizz

    def getSharedSecret(self):
        return self.__sharedSecret

    def setSharedSecret(self,secret):
        self.__sharedSecret = secret

    def setSha348(self,sha348):
        self.__sha384 = sha348

    def setResponse(self):
        self.__response = True
