
import { createStore, applyMiddleware, compose } from 'redux';
import thunk from 'redux-thunk';
import rootReducer from './reducers/index';
const middleware = [thunk]
const store = 
createStore(
    rootReducer, 
    {}, 
    compose(applyMiddleware(...middleware), 
    typeof window.__REDUX_DEVTOOLS_EXTENSION__ !== 'undefined' ? window.__REDUX_DEVTOOLS_EXTENSION__(): compose )
    );

export default store;
