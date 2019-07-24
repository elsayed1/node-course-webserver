
const initState = {
    posts: [],
    post: {}
}

const postReducer = (state=initState, action) => {
    switch(action.type){
        case 'ADD_POST':
        return {
            posts: [action.payload, ...state.posts]
        }
        case 'GET_POSTS':
            return{
                ...state,
                post: null,
                posts: action.payload
            }
        case 'GET_POST':
            return{
                ...state,
                post: action.payload
            }
        default: 
            return state;
    }
}
export default postReducer;