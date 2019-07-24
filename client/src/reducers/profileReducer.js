const initState = {
    profile: null,
    profiles: null,
}


export default (state=initState, action) => {
    switch(action.type){
        case 'GET_PROFILE':
            return {
                ...state,
                profile: action.payload,
            }
        case 'CLEAR_PROFILE':
            return {
                ...state,
                profile: null
            }
        case 'GET_PROFILES':
            return{
                ...state,
                profiles: action.payload
            }
        default:
            return state;
    }
}