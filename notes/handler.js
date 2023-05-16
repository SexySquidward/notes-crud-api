'use strict';
const DynamoDB = require("aws-sdk/clients/dynamodb")
const documentClient = new DynamoDB.DocumentClient({
  region: 'ap-southeast-2',
  maxRetries: 3,
  httpOptions: {
    timeout: 5000
  }
  });
const NOTES_TABLE_NAME = process.env.NOTES_TABLE_NAME;

const send = (statusCode, data) => {
  return {
    statusCode,
    body: JSON.stringify(data)
  }
}



module.exports.createNote = async (event, context, callback) => {
  context.callbackWaitsForEmptyEventLoop = false
  let data = JSON.parse(event.body);
  try {
    const params = {
      TableName: NOTES_TABLE_NAME,
      Item: {
        notesId: data.id,
        title: data.title,
        body: data.body
      },
      ConditionExpression: "attribute_not_exists(notesId)"
    }
    await documentClient.put(params).promise();
    callback(null, send(201, data))
  } catch (error) {
    callback(null, send(500, error.message))
  }
  
};
module.exports.updateNote = async (event, context,callback) => {
  context.callbackWaitsForEmptyEventLoop = false
  let notesId = event.pathParameters.id
  let data = JSON.parse(event.body);
  try {
    const params = {
      TableName: NOTES_TABLE_NAME,
      Key: { notesId },
      UpdateExpression: 'set #title = :title, #body = :body',
      ExpressionAttributeNames: {
        '#title' : 'title',
        "#body": 'body'
      },
      ExpressionAttributeValues: {
        ':title': data.title,
        ':body': data.body
      },
      ConditionExpression: "attribute_exists(notesId)"
    }
    await documentClient.update(params).promise();
    callback(null, send(200, data))
  } catch (error) {
    callback(null, send(500, error.message))
  } 


 
};
module.exports.deleteNote = async (event, context, callback) => {
  context.callbackWaitsForEmptyEventLoop = false
  let notesId = event.pathParameters.id
  try {
    const params = {
      TableName: NOTES_TABLE_NAME,
      Key: {notesId},
      ConditionExpression: "attribute_exists(notesId)"
    }
    await documentClient.delete(params).promise();
    callback(null,send(200, notesId))
  } catch (error) {
    callback(null, send(500, error.message))
  }
};
module.exports.getAllNotes = async (event, context, callback) => {
  context.callbackWaitsForEmptyEventLoop = false
  try {
    const params = {
      TableName: NOTES_TABLE_NAME
    }
    const notes = await documentClient.scan(params).promise();
    callback(null,send(200,notes))
  } catch (error) {
    callback(null, send(500, error.message))
  }
};