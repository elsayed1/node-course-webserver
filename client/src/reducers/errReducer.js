
const inintialState = {};
export default function(state=inintialState, action){
    switch(action.type){
        case 'GET-ERRORS':
            return action.payload;
        default:
            return state
    }
}