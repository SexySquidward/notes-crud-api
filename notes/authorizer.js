const {CognitoJwtVerifier} = require("aws-jwt-verify")
const COGNITO_USERPOOL_ID = process.env.COGNITO_USERPOOL_ID;
const COGNITO_WEB_CLIENT_ID = process.env.COGNITO_WEB_CLIENT_ID
const jwtVerifer = CognitoJwtVerifier.create({
    userPoolId: COGNITO_USERPOOL_ID,
    tokenUse: "id",
    clientId: COGNITO_WEB_CLIENT_ID
})

const generatePolicy = (principalId, effect, resource) => {
    var authResponse = {}
    authResponse.principalId = principalId
    if(effect && resource){
        let policyDocument = {
            Version: "2012-10-17",
            Statement: [
                {
                    Effect: effect,
                    Resource: resource,
                    Action: "execute-api:Invoke",

                },
            ],
        };
        authResponse.policyDocument = policyDocument
    }

    authResponse.context = {
        foo: "bar"
    }
   
    return authResponse;
}




exports.handler = async (event, context, callback) => {
    var token = event.authorizationToken; //allow or deny
    console.log(token)
    try {
        const payload =  await jwtVerifer.verify(token);
        console.log(JSON.stringify(payload));
        callback(null, generatePolicy("user","Allow", event.methodArn))
    } catch (error) {
        callback("Error: Invalid Token");
    }


}